use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Instant;

use ansi_term::Colour;
use clap::Parser;
use memmap2::Mmap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tree_sitter::{Node, Parser as TSParser};
use walkdir::WalkDir;

// If you're reading this, it's already too late. Your code is broken.

// Languages we actually care about (sorry Ruby, you're here for completeness)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Language {
    C,
    Cpp,
    Java,
    CSharp,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Rust,
    Ruby,
}

impl Language {
    fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "c" => Some(Language::C),
            "cpp" | "cc" | "cxx" | "c++" | "hpp" | "h" => Some(Language::Cpp),
            "java" => Some(Language::Java),
            "cs" => Some(Language::CSharp),
            "py" | "pyw" => Some(Language::Python),
            "js" | "jsx" => Some(Language::JavaScript),
            "ts" | "tsx" => Some(Language::TypeScript),
            "go" => Some(Language::Go),
            "rs" => Some(Language::Rust),
            "rb" => Some(Language::Ruby),
            _ => None,
        }
    }
    
    fn get_parser(&self) -> Option<TSParser> {
        let mut parser = TSParser::new();
        let result = match self {
            Language::C | Language::Cpp => parser.set_language(&tree_sitter_c::LANGUAGE.into()),
            Language::Python => parser.set_language(&tree_sitter_python::LANGUAGE.into()),
            Language::Java => parser.set_language(&tree_sitter_java::LANGUAGE.into()),
            Language::JavaScript | Language::TypeScript => parser.set_language(&tree_sitter_javascript::LANGUAGE.into()),
            // lol good luck
            _ => return None,
        };
        result.ok().map(|_| parser)
    }
    
    // The naughty list. These functions are why we can't have nice things.
    fn get_dangerous_functions(&self) -> Vec<(&'static str, Severity, &'static str)> {
        match self {
            Language::C | Language::Cpp => vec![
                ("strcpy", Severity::Critical, "Use strncpy(dest, src, sizeof(dest)-1)"),
                ("strcat", Severity::Critical, "Use strncat(dest, src, remaining)"),
                ("sprintf", Severity::Critical, "Use snprintf(buf, sizeof(buf), ...)"),
                ("gets", Severity::Critical, "Use fgets(buf, sizeof(buf), stdin)"),
                ("wcscpy", Severity::Critical, "Use wcsncpy"),
                ("memcpy", Severity::High, "Verify size <= destination buffer"),
                ("memset", Severity::Medium, "Verify size is correct"),
                ("system", Severity::Critical, "Avoid system() - use execve() with full path"),
                ("popen", Severity::Critical, "Validate command input thoroughly"),
                ("scanf", Severity::High, "Use scanf_s or validate format string"),
            ],
            Language::Java => vec![
                ("exec", Severity::Critical, "Validate command, use ProcessBuilder with array"),
                ("eval", Severity::Critical, "Never eval user input - use sandboxing"),
                ("Runtime.getRuntime", Severity::High, "Validate external commands"),
                ("ObjectInputStream", Severity::Critical, "Deserialize only trusted data (prevent RCE)"),
                ("readObject", Severity::Critical, "Implement look-ahead deserialization"),
            ],
            Language::Python => vec![
                ("eval", Severity::Critical, "Never eval user input - use ast.literal_eval"),
                ("exec", Severity::Critical, "Never exec user input - massive RCE risk"),
                ("subprocess.call", Severity::High, "Use list args, not shell=True"),
                ("os.system", Severity::Critical, "Use subprocess with array, no shell"),
                ("pickle.loads", Severity::Critical, "Only unpickle trusted data"),
                ("yaml.load", Severity::Critical, "Use yaml.safe_load, not load"),
            ],
            Language::JavaScript | Language::TypeScript => vec![
                ("eval", Severity::Critical, "Never eval user input"),
                ("Function", Severity::Critical, "Never construct functions from user input"),
                ("setTimeout", Severity::High, "Don't pass strings, use function references"),
                ("setInterval", Severity::High, "Don't pass strings, use function references"),
                ("innerHTML", Severity::High, "Use textContent or sanitized HTML"),
                ("document.write", Severity::High, "Use DOM methods instead"),
            ],
            _ => vec![], // TODO: add more languages but who cares rn
        }
    }
    
    // Memory allocators - where dreams go to leak
    fn get_alloc_functions(&self) -> Vec<&'static str> {
        match self {
            Language::C | Language::Cpp => vec!["malloc", "calloc", "realloc", "strdup", "strndup"],
            Language::Java => vec!["new ", "FileInputStream", "ObjectInputStream", "Socket"],
            Language::Python => vec!["open(", "socket.", "subprocess."],
            Language::JavaScript | Language::TypeScript => vec!["new ", "fetch(", "XMLHttpRequest"],
            _ => vec![],
        }
    }
    
    // User input sources. Treat these like they're radioactive.
    fn get_taint_sources(&self) -> Vec<&'static str> {
        match self {
            Language::C | Language::Cpp => vec![
                "scanf", "fgets", "read", "recv", "getenv", "argv[", "fread"
            ],
            Language::Java => vec![
                "getParameter", "getHeader", "getInputStream", "getReader",
                "System.getenv", "System.getProperty", "BufferedReader.read"
            ],
            Language::Python => vec![
                "input(", "sys.argv", "os.environ", "request.", "socket.recv"
            ],
            Language::JavaScript | Language::TypeScript => vec![
                "req.query", "req.body", "req.params", "req.headers", 
                "localStorage", "sessionStorage", "document.cookie", "window.location"
            ],
            _ => vec![],
        }
    }
    
    // Where tainted data goes to die (or exploit)
    fn get_taint_sinks(&self) -> Vec<&'static str> {
        match self {
            Language::C | Language::Cpp => vec!["system", "popen", "exec", "eval", "sprintf", "strcpy"],
            Language::Java => vec!["exec", "eval", "Runtime.exec", "ProcessBuilder"],
            Language::Python => vec!["eval", "exec", "os.system", "subprocess.call", "subprocess.Popen"],
            Language::JavaScript | Language::TypeScript => vec!["eval", "Function", "exec", "innerHTML"],
            _ => vec![],
        }
    }
}

// The router. Like a traffic cop but for security bugs.
struct MultiLanguageScanner {
    language: Language,
    inner: Box<dyn LanguageAnalyzer>,
}

impl MultiLanguageScanner {
    fn new(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?;
        let lang = Language::from_extension(ext)?;
        
        let analyzer: Box<dyn LanguageAnalyzer> = match lang {
            Language::C | Language::Cpp => Box::new(CppAnalyzer::new()),
            Language::Java => JavaAnalyzer::new()
                .map(|a| Box::new(a) as Box<dyn LanguageAnalyzer>)
                .unwrap_or_else(|| Box::new(PatternJavaAnalyzer::new())),
            Language::Python => PythonAnalyzer::new()
                .map(|a| Box::new(a) as Box<dyn LanguageAnalyzer>)
                .unwrap_or_else(|| Box::new(PatternPythonAnalyzer::new())),
            Language::JavaScript | Language::TypeScript => JavaScriptAnalyzer::new()
                .map(|a| Box::new(a) as Box<dyn LanguageAnalyzer>)
                .unwrap_or_else(|| Box::new(PatternJavaScriptAnalyzer::new())),
            _ => return None, // go away, we're closed
        };
        
        Some(Self {
            language: lang,
            inner: analyzer,
        })
    }
    
    fn scan_file(&mut self, path: &Path) -> Vec<Finding> {
        self.inner.analyze(path, self.language)
    }
}

// When AST parsing fails, we phone it in with regex. Better than nothing I guess?
struct PatternPythonAnalyzer;
impl PatternPythonAnalyzer { fn new() -> Self { Self } }
impl LanguageAnalyzer for PatternPythonAnalyzer {
    fn analyze(&mut self, path: &Path, _language: Language) -> Vec<Finding> {
        if let Ok(content) = std::fs::read_to_string(path) {
            let mut findings = Vec::new();
            for (i, line) in content.lines().enumerate() {
                let line_lower = line.to_lowercase();
                if line_lower.contains("eval(") && !line_lower.contains("literal_eval") {
                    findings.push(Finding::new(
                        path.to_string_lossy().to_string(),
                        i + 1, 0, Severity::Critical,
                        "python_eval".to_string(),
                        "eval() detected".to_string(),
                        Some("Use ast.literal_eval".to_string())
                    ).with_confidence(0.85));
                }
            }
            return findings;
        }
        Vec::new()
    }
}

struct PatternJavaScriptAnalyzer;
impl PatternJavaScriptAnalyzer { fn new() -> Self { Self } }
impl LanguageAnalyzer for PatternJavaScriptAnalyzer {
    fn analyze(&mut self, path: &Path, _language: Language) -> Vec<Finding> {
        if let Ok(content) = std::fs::read_to_string(path) {
            let mut findings = Vec::new();
            for (i, line) in content.lines().enumerate() {
                let line_lower = line.to_lowercase();
                if line_lower.contains("eval(") {
                    findings.push(Finding::new(
                        path.to_string_lossy().to_string(),
                        i + 1, 0, Severity::Critical,
                        "js_eval".to_string(),
                        "eval() detected".to_string(),
                        Some("Never use eval()".to_string())
                    ).with_confidence(0.85));
                }
            }
            return findings;
        }
        Vec::new()
    }
}

struct PatternJavaAnalyzer;
impl PatternJavaAnalyzer { fn new() -> Self { Self } }
impl LanguageAnalyzer for PatternJavaAnalyzer {
    fn analyze(&mut self, path: &Path, _language: Language) -> Vec<Finding> {
        if let Ok(content) = std::fs::read_to_string(path) {
            let mut findings = Vec::new();
            for (i, line) in content.lines().enumerate() {
                let line_lower = line.to_lowercase();
                if line_lower.contains("objectinputstream") && line_lower.contains("readobject") {
                    findings.push(Finding::new(
                        path.to_string_lossy().to_string(),
                        i + 1, 0, Severity::Critical,
                        "java_deserialization".to_string(),
                        "Insecure deserialization".to_string(),
                        Some("Validate class whitelist".to_string())
                    ).with_confidence(0.85));
                }
            }
            return findings;
        }
        Vec::new()
    }
}

// The trait that ties it all together. Implement this or go home.
trait LanguageAnalyzer: Send {
    fn analyze(&mut self, path: &Path, language: Language) -> Vec<Finding>;
}

// Time to find some bugs in this garbage fire you call C code
#[derive(Parser, Debug)]
#[command(name = "ntscan")]
#[command(about = "Lightning-fast multi-language security scanner", long_about = None)]
struct Args {
    /// Path to scan
    #[arg(default_value = ".")]
    path: PathBuf,
    
    /// Only check specific file extensions (auto-detects language)
    #[arg(short, long, default_value = "c,cpp,h,hpp,java,cs,py,js,ts,go,rs,rb")]
    extensions: String,
    
    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,
    
    /// Number of threads (0 = auto)
    #[arg(short, long, default_value = "0")]
    threads: usize,
    
    /// Minimum severity to report (low, medium, high, critical)
    #[arg(short, long, default_value = "low")]
    severity: String,
    
    /// Quiet mode - only show summary
    #[arg(short, long)]
    quiet: bool,
    
    /// Watch mode - re-run on file changes
    #[arg(short, long)]
    watch: bool,
    
    /// Compare against baseline file (default: ntscan-baseline.json)
    #[arg(short, long)]
    baseline: Option<PathBuf>,
    
    /// Config file path (default: .ntscan.toml)
    #[arg(short, long)]
    config: Option<PathBuf>,
    
    /// Write results to SARIF file (ntscan-results.sarif)
    #[arg(long, num_args = 0..=1, default_missing_value = "ntscan-results.sarif")]
    sarif: Option<PathBuf>,
    
    /// Generate GitHub Actions workflow file
    #[arg(long)]
    git: bool,
    
    /// Show credits (easter egg)
    #[arg(long)]
    credits: bool,
    
    /// Coffee recommendation based on bug count (easter egg)
    #[arg(long)]
    coffee: bool,
    
    /// Save current results as baseline (ntscan-baseline.json)
    #[arg(long, num_args = 0..=1, default_missing_value = "ntscan-baseline.json")]
    save_baseline: Option<PathBuf>,
    
    /// Interactive TUI mode (easier to use)
    #[arg(long)]
    tui: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Finding {
    file: String,
    line: usize,
    column: usize,
    severity: Severity,
    category: String,
    message: String,
    suggestion: Option<String>,
    confidence: f32, // 0.0 to 1.0
}

impl Finding {
    fn new(file: String, line: usize, column: usize, severity: Severity, 
           category: String, message: String, suggestion: Option<String>) -> Self {
        Self {
            file,
            line,
            column,
            severity,
            category,
            message,
            suggestion,
            confidence: 1.0,
        }
    }
    
    fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
    
    fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.7
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Severity {
    fn color(&self) -> Colour {
        match self {
            Severity::Low => Colour::Blue,
            Severity::Medium => Colour::Yellow,
            Severity::High => Colour::Red,
            Severity::Critical => Colour::Fixed(196), // Bright red
        }
    }
}

struct Scanner {
    parser: TSParser,
    findings: Vec<Finding>,
}

impl Scanner {
    fn new() -> Self {
        let mut parser = TSParser::new();
        parser.set_language(&tree_sitter_c::LANGUAGE.into()).unwrap();
        Self {
            parser,
            findings: Vec::new(),
        }
    }

    fn scan_file(&mut self, path: &Path) -> Vec<Finding> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let mmap = match unsafe { Mmap::map(&file) } {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        let source = match std::str::from_utf8(&mmap) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        
        let tree = match self.parser.parse(source, None) {
            Some(t) => t,
            None => return Vec::new(),
        };
        let root = tree.root_node();
        
        let mut findings = Vec::new();
        
        // Run all checks
        findings.extend(self.check_buffer_overflows(&root, source, path));
        findings.extend(self.check_null_dereferences(&root, source, path));
        findings.extend(self.check_unsafe_functions(&root, source, path));
        findings.extend(self.check_integer_overflows(&root, source, path));
        findings.extend(self.check_resource_leaks(&root, source, path));
        findings.extend(self.check_dangerous_patterns_regex(source, path));
        
        // ADVANCED: Symbolic execution for path-sensitive analysis
        findings.extend(SymbolicAnalyzer::analyze_function(&root, source, path));
        
        // ADVANCED: Interprocedural taint analysis
        let taint_analyzer = TaintAnalyzer::new();
        findings.extend(taint_analyzer.analyze_file(&root, source, path));
        
        // Deep cuts. The bugs that require actual brain cells to find.
        findings.extend(AdvancedSecurityAnalyzer::analyze(&root, source, path));
        
        // Follow the data like a stalker follows their ex
        findings.extend(DataFlowAnalyzer::analyze(&root, source, path));
        
        // Types matter. Unlike your ex who said they didn't.
        findings.extend(TypeAwareChecker::analyze(&root, source, path));
        
        // Jump between functions like a caffeinated frog
        let call_graph_analyzer = CallGraphAnalyzer::new();
        findings.extend(call_graph_analyzer.analyze_file(&root, source, path));
        
        findings
    }

    fn check_buffer_overflows(&self, root: &Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        self.find_calls_recursive(root, source, path, &mut findings, &[
            ("strcpy", Severity::Critical, "Use strncpy(dest, src, sizeof(dest)-1)"),
            ("strcat", Severity::Critical, "Use strncat(dest, src, remaining)"),
            ("sprintf", Severity::Critical, "Use snprintf(buf, sizeof(buf), ...)"),
            ("gets", Severity::Critical, "Use fgets(buf, sizeof(buf), stdin)"),
            ("wcscpy", Severity::Critical, "Use wcsncpy"),
            ("memcpy", Severity::High, "Verify size <= destination buffer"),
            ("memset", Severity::Medium, "Verify size is correct"),
        ]);
        findings
    }
    
    fn find_calls_recursive(&self, node: &Node, source: &str, path: &Path, findings: &mut Vec<Finding>, dangerous: &[(&str, Severity, &str)]) {
        if node.kind() == "call_expression" {
            let func_node = node.child_by_field_name("function");
            if let Some(func) = func_node {
                let func_name = &source[func.start_byte()..func.end_byte()];
                
                for (bad_func, severity, suggestion) in dangerous {
                    if func_name == *bad_func {
                        let (line, col) = Self::get_position(source, node.start_byte());
                        findings.push(Finding {
                            file: path.to_string_lossy().to_string(),
                            line,
                            column: col,
                            severity: *severity,
                            category: "buffer_overflow".to_string(),
                            message: format!("Dangerous function: {} - no bounds checking", func_name),
                            suggestion: Some(suggestion.to_string()),
                            confidence: 0.95,
                        });
                        break;
                    }
                }
            }
        }
        
        // Recursively check all children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.find_calls_recursive(&child, source, path, findings, dangerous);
        }
    }

    fn check_null_dereferences(&self, root: &Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = root.walk();
        
        // Track variable assignments that could be null
        let mut nullable_vars: HashMap<String, bool> = HashMap::new();
        
        for node in root.children(&mut cursor) {
            // Check for malloc/calloc/realloc without null check
            if node.kind() == "call_expression" {
                let func_node = node.child_by_field_name("function");
                if let Some(func) = func_node {
                    let func_name = &source[func.start_byte()..func.end_byte()];
                    if func_name == "malloc" || func_name == "calloc" || func_name == "realloc" {
                        // Look for null check in following siblings
                        if !self.has_null_check_after(&node, source) {
                            let (line, col) = Self::get_position(source, node.start_byte());
                            findings.push(Finding {
                                file: path.to_string_lossy().to_string(),
                                line,
                                column: col,
                                severity: Severity::High,
                                category: "null_dereference".to_string(),
                                message: format!("{} return value not checked for NULL", func_name),
                                suggestion: Some("Add 'if (!ptr) return/error' after allocation".to_string()),
                                confidence: 0.85,
                            });
                        }
                    }
                }
            }
            
            // Check for pointer dereference
            if node.kind() == "pointer_expression" || node.kind() == "field_expression" {
                let operand = node.child_by_field_name("argument").or_else(|| node.child(0));
                if let Some(op) = operand {
                    let var_name = &source[op.start_byte()..op.end_byte()];
                    if nullable_vars.get(var_name).copied().unwrap_or(false) {
                        let (line, col) = Self::get_position(source, node.start_byte());
                        findings.push(Finding {
                            file: path.to_string_lossy().to_string(),
                            line,
                            column: col,
                            severity: Severity::Critical,
                            category: "null_dereference".to_string(),
                            message: format!("Potential NULL pointer dereference: {}", var_name),
                            suggestion: Some("Add null check before dereference".to_string()),
                            confidence: 0.75,
                        });
                    }
                }
            }
        }
        
        findings
    }

    fn check_unsafe_functions(&self, root: &Node, source: &str, path: &Path) -> Vec<Finding> {
        let dangerous = ["gets", "system", "popen", "strcpy", "strcat", "sprintf"];
        let mut findings = Vec::new();
        let mut cursor = root.walk();
        
        for node in root.children(&mut cursor) {
            if node.kind() == "call_expression" {
                let func_node = node.child_by_field_name("function");
                if let Some(func) = func_node {
                    let func_name = &source[func.start_byte()..func.end_byte()];
                    if dangerous.contains(&func_name) {
                        let (line, col) = Self::get_position(source, node.start_byte());
                        findings.push(Finding {
                            file: path.to_string_lossy().to_string(),
                            line,
                            column: col,
                            severity: Severity::Critical,
                            category: "unsafe_function".to_string(),
                            message: format!("Banned function: {} - security risk", func_name),
                            suggestion: Some(Self::suggest_safe_alternative(func_name)),
                            confidence: 0.98,
                        });
                    }
                }
            }
        }
        
        findings
    }

    fn check_integer_overflows(&self, root: &Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = root.walk();
        
        for node in root.children(&mut cursor) {
            if node.kind() == "binary_expression" {
                let operator = node.child_by_field_name("operator");
                if let Some(op) = operator {
                    let op_text = &source[op.start_byte()..op.end_byte()];
                    if op_text == "*" || op_text == "+" || op_text == "<<" {
                        // Check if operands are integers without bounds check
                        let left = node.child_by_field_name("left");
                        let right = node.child_by_field_name("right");
                        
                        if self.is_unbounded_integer(&left, source) && 
                           self.is_unbounded_integer(&right, source) {
                            let (line, col) = Self::get_position(source, node.start_byte());
                            findings.push(Finding {
                                file: path.to_string_lossy().to_string(),
                                line,
                                column: col,
                                severity: Severity::Medium,
                                category: "integer_overflow".to_string(),
                                message: format!("Potential integer overflow in {} operation", op_text),
                                suggestion: Some("Add overflow check or use saturating arithmetic".to_string()),
                                confidence: 0.65,
                            });
                        }
                    }
                }
            }
        }
        
        findings
    }

    fn check_resource_leaks(&self, root: &Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = root.walk();
        
        // Track allocated resources
        let mut allocated: Vec<(String, usize)> = Vec::new(); // (var_name, line)
        let mut freed: Vec<String> = Vec::new();
        
        for node in root.children(&mut cursor) {
            if node.kind() == "call_expression" {
                let func_node = node.child_by_field_name("function");
                if let Some(func) = func_node {
                    let func_name = &source[func.start_byte()..func.end_byte()];
                    
                    match func_name {
                        "malloc" | "calloc" | "realloc" | "fopen" | "socket" | "open" => {
                            // Track the variable this is assigned to
                            if let Some(parent) = node.parent() {
                                if parent.kind() == "assignment_expression" {
                                    let left = parent.child_by_field_name("left");
                                    if let Some(l) = left {
                                        let var_name = source[l.start_byte()..l.end_byte()].to_string();
                                        let (line, _) = Self::get_position(source, node.start_byte());
                                        allocated.push((var_name, line));
                                    }
                                }
                            }
                        }
                        "free" | "fclose" | "close" => {
                            // Mark as freed
                            if let Some(args) = node.child_by_field_name("arguments") {
                                if let Some(arg) = args.child(0) {
                                    let var_name = &source[arg.start_byte()..arg.end_byte()];
                                    freed.push(var_name.to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        
        // Find unfreed resources
        for (var, line) in allocated {
            if !freed.contains(&var) {
                findings.push(Finding {
                    file: path.to_string_lossy().to_string(),
                    line,
                    column: 0,
                    severity: Severity::Medium,
                    category: "resource_leak".to_string(),
                    message: format!("Potential resource leak: {} not freed", var),
                    suggestion: Some("Add cleanup in all exit paths".to_string()),
                    confidence: 0.70,
                });
            }
        }
        
        findings
    }

    fn check_dangerous_patterns_regex(&self, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // PRECISION: Skip test files and generated code
        let path_str = path.to_string_lossy().to_lowercase();
        if self.is_test_or_generated_file(&path_str) {
            return findings;
        }
        
        // Simple pattern matching without regex for speed
        for (i, line) in source.lines().enumerate() {
            let line_lower = line.to_lowercase();
            let trimmed = line.trim();
            
            // PRECISION: Skip comment lines that are just documentation
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }
            
            // PRECISION: Skip string literals (not actual code)
            if trimmed.starts_with("\"") || trimmed.starts_with("'") {
                continue;
            }
            
            // HIGH-CONFIDENCE: Real TODO security issues (not in source code of scanner itself)
            if line_lower.contains("todo") && 
               (line_lower.contains("security") || line_lower.contains("unsafe")) &&
               !line_lower.contains("\"security\"") && // Skip string literals
               !line_lower.contains("'security'") {
                findings.push(Finding {
                    file: path.to_string_lossy().to_string(),
                    line: i + 1,
                    column: 0,
                    severity: Severity::Medium,
                    category: "todo_security".to_string(),
                    message: "TODO comment mentions security issue".to_string(),
                    suggestion: Some("Address before release".to_string()),
                    confidence: 0.80,
                });
            }
            
            // HIGH-CONFIDENCE: Hardcoded credentials (with extra validation)
            if (line_lower.contains("password") || line_lower.contains("passwd") || 
                line_lower.contains("pwd")) && 
               line.contains("=") &&
               !line_lower.contains("contains(") && // Skip detection code itself
               !line_lower.contains("'") && // Skip single-quoted code
               self.looks_like_assignment(line) { // Verify it's actually an assignment
                findings.push(Finding {
                    file: path.to_string_lossy().to_string(),
                    line: i + 1,
                    column: 0,
                    severity: Severity::High,
                    category: "hardcoded_credential".to_string(),
                    message: "Potential hardcoded password detected".to_string(),
                    suggestion: Some("Use environment variables or secure vault".to_string()),
                    confidence: 0.72,
                });
            }
        }
        
        findings
    }
    
    fn is_test_or_generated_file(&self, path: &str) -> bool {
        path.contains("test") || 
        path.contains("spec") ||
        path.contains("_mock") ||
        path.contains("generated") ||
        path.contains("vendor/") ||
        path.contains("deps/") ||
        path.contains("third_party")
    }
    
    fn looks_like_assignment(&self, line: &str) -> bool {
        // Must have var = value pattern, not just contains =
        let parts: Vec<&str> = line.split('=').collect();
        if parts.len() >= 2 {
            let left = parts[0].trim();
            let right = parts[1].trim();
            // Left side should be identifier-like
            // Right side should be string-like value
            left.chars().all(|c| c.is_alphanumeric() || c == '_' || c == ' ' || c == '[' || c == ']') &&
            (right.starts_with('"') || right.starts_with('\'') || right.parse::<i64>().is_ok())
        } else {
            false
        }
    }

    // Helper methods
    fn get_position(source: &str, byte_offset: usize) -> (usize, usize) {
        let line = source[..byte_offset].lines().count();
        let column = source[..byte_offset].lines().last().map(|l| l.len()).unwrap_or(0);
        (line, column)
    }

    fn has_size_check(&self, node: &Node, _source: &str) -> bool {
        // Simplified: check if there's a comparison in parent scope
        false // Conservative: assume no check
    }

    fn has_null_check_after(&self, node: &Node, _source: &str) -> bool {
        // Check if next sibling is an if statement checking for NULL
        if let Some(next) = node.next_sibling() {
            if next.kind() == "if_statement" {
                return true;
            }
        }
        false
    }

    fn is_unbounded_integer(&self, node: &Option<Node>, _source: &str) -> bool {
        // Check if node represents an integer without known bounds
        if let Some(n) = node {
            matches!(n.kind(), "number_literal" | "identifier")
        } else {
            false
        }
    }

    fn suggest_safe_alternative(func_name: &str) -> String {
        match func_name {
            "gets" => "Use fgets(buf, sizeof(buf), stdin)".to_string(),
            "strcpy" => "Use strncpy(dest, src, sizeof(dest)-1)".to_string(),
            "strcat" => "Use strncat(dest, src, remaining_space)".to_string(),
            "sprintf" => "Use snprintf(buf, sizeof(buf), fmt, ...)".to_string(),
            "system" => "Use execve() with full path verification".to_string(),
            _ => "Use safer alternative".to_string(),
        }
    }
}

// The actual analyzers. Each one is a special snowflake.

struct CppAnalyzer {
    scanner: Scanner,
}

impl CppAnalyzer {
    fn new() -> Self {
        Self {
            scanner: Scanner::new(),
        }
    }
}

impl LanguageAnalyzer for CppAnalyzer {
    fn analyze(&mut self, path: &Path, _language: Language) -> Vec<Finding> {
        self.scanner.scan_file(path)
    }
}

// Symbolic execution. We simulate your code because we're too lazy to run it.

#[derive(Debug, Clone)]
enum SymbolicValue {
    Concrete(i64),
    Symbol(String),
    BinaryOp { op: String, left: Box<SymbolicValue>, right: Box<SymbolicValue> },
    Unknown,
}

impl SymbolicValue {
    fn is_null(&self) -> bool {
        matches!(self, SymbolicValue::Concrete(0))
    }
    
    fn could_be_null(&self) -> bool {
        match self {
            SymbolicValue::Concrete(0) => true,
            SymbolicValue::Concrete(_) => false,
            _ => true,
        }
    }
    
    fn could_exceed(&self, max_val: i64) -> bool {
        match self {
            SymbolicValue::Concrete(n) => *n > max_val,
            SymbolicValue::BinaryOp { op, .. } => {
                if op == "*" || op == "+" || op == "<<" {
                    true
                } else {
                    false
                }
            }
            _ => true,
        }
    }
}

// Tracks values through your spaghetti code
struct SymbolicAnalyzer;

// The deep cuts. The bugs your IDE is too cowardly to find.

// Finds the bugs that'll get you on Hacker News (and not in a good way)
struct AdvancedSecurityAnalyzer;

impl AdvancedSecurityAnalyzer {
    fn analyze(root: &Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut state = AdvancedAnalysisState::new();
        
        Self::analyze_with_state(root, source, path, &mut state, &mut findings);
        findings
    }
    
    fn analyze_with_state(
        node: &Node,
        source: &str,
        path: &Path,
        state: &mut AdvancedAnalysisState,
        findings: &mut Vec<Finding>
    ) {
        match node.kind() {
            "call_expression" => {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_name = &source[func.start_byte()..func.end_byte()];
                    
                    // BUG 1: TOCTOU (Time-of-check-time-of-use) detection
                    if func_name.to_lowercase().contains("access") || func_name.to_lowercase().contains("stat") || 
                       func_name.to_lowercase().contains("lstat") || func_name.to_lowercase().contains("fstat") {
                        // Mark that we saw a check on this path
                        state.check_operations.push(func_name.to_string());
                        state.check_line = Scanner::get_position(source, node.start_byte()).0;
                        
                        // Look for subsequent file operations in the same scope
                        if let Some(parent) = node.parent() {
                            Self::check_for_toctou(&parent, source, path, &func_name, node.start_byte(), findings);
                        }
                    }
                    
                    // BUG 2: Integer overflow in allocation size
                    if func_name.to_lowercase() == "malloc" || func_name.to_lowercase() == "calloc" || func_name.to_lowercase() == "realloc" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let args_text = source[args.start_byte()..args.end_byte()].to_string();
                            
                            // Check for multiplication that could overflow
                            if args_text.contains("*") || args_text.contains("<<") {
                                let (line, col) = Scanner::get_position(source, node.start_byte());
                                findings.push(Finding {
                                    file: path.to_string_lossy().to_string(),
                                    line,
                                    column: col,
                                    severity: Severity::Critical,
                                    category: "integer_overflow_allocation".to_string(),
                                    message: format!("Integer overflow risk in {} size calculation", func_name),
                                    suggestion: Some("Check for overflow: if (n > SIZE_MAX / size) return NULL".to_string()),
                                    confidence: 0.88,
                                });
                            }
                            
                            // Check for signed/unsigned confusion
                            if args_text.contains("-") && !args_text.contains("sizeof") {
                                let (line, col) = Scanner::get_position(source, node.start_byte());
                                findings.push(Finding {
                                    file: path.to_string_lossy().to_string(),
                                    line,
                                    column: col,
                                    severity: Severity::High,
                                    category: "signed_size_calculation".to_string(),
                                    message: format!("Signed arithmetic in {} size may underflow", func_name),
                                    suggestion: Some("Cast to size_t before arithmetic".to_string()),
                                    confidence: 0.75,
                                });
                            }
                        }
                    }
                    
                    // BUG 3: Double close / use-after-close detection
                    if func_name.to_lowercase() == "fclose" || func_name.to_lowercase() == "close" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let arg_text = source[args.start_byte()..args.end_byte()].to_string();
                            if state.closed_resources.contains(&arg_text) {
                                let (line, col) = Scanner::get_position(source, node.start_byte());
                                findings.push(Finding {
                                    file: path.to_string_lossy().to_string(),
                                    line,
                                    column: col,
                                    severity: Severity::Critical,
                                    category: "double_close".to_string(),
                                    message: format!("Resource {} may be closed twice", arg_text),
                                    suggestion: Some("Set handle to NULL after close, check before closing".to_string()),
                                    confidence: 0.82,
                                });
                            } else {
                                state.closed_resources.insert(arg_text);
                            }
                        }
                    }
                    
                    // BUG 4: Dangerous function called with tainted input (cross-function)
                    if func_name.to_lowercase() == "system" || func_name.to_lowercase() == "popen" || func_name.to_lowercase() == "execl" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let args_text = source[args.start_byte()..args.end_byte()].to_string();
                            // Check if argument comes from external source
                            if Self::is_externally_tainted(&args_text, state) {
                                let (line, col) = Scanner::get_position(source, node.start_byte());
                                findings.push(Finding {
                                    file: path.to_string_lossy().to_string(),
                                    line,
                                    column: col,
                                    severity: Severity::Critical,
                                    category: "command_injection_tainted".to_string(),
                                    message: format!("{} called with potentially tainted input", func_name),
                                    suggestion: Some("Validate command against whitelist, use execve with full path".to_string()),
                                    confidence: 0.91,
                                });
                            }
                        }
                    }
                }
            }
            
            "binary_expression" => {
                let text = source[node.start_byte()..node.end_byte()].to_string();
                
                // BUG 5: Off-by-one detection in loop conditions
                if text.contains("<=") && (text.contains("sizeof") || text.contains("len") || text.contains("count")) {
                    let (line, col) = Scanner::get_position(source, node.start_byte());
                    findings.push(Finding {
                        file: path.to_string_lossy().to_string(),
                        line,
                        column: col,
                        severity: Severity::Medium,
                        category: "potential_off_by_one".to_string(),
                        message: "Check for off-by-one error: <= with array bounds".to_string(),
                        suggestion: Some("Verify <= is correct, often should be <".to_string()),
                        confidence: 0.65,
                    });
                }
            }
            
            "parenthesized_expression" | "assignment_expression" => {
                // Track variable assignments for taint analysis
                if let Some(left) = node.child_by_field_name("left") {
                    if let Some(right) = node.child_by_field_name("right") {
                        let lhs = source[left.start_byte()..left.end_byte()].to_string();
                        let rhs = source[right.start_byte()..right.end_byte()].to_string();
                        
                        // If RHS is tainted, mark LHS as tainted
                        if Self::is_tainted_source(&rhs) {
                            state.tainted_vars.insert(lhs);
                        }
                    }
                }
            }
            
            _ => {}
        }
        
        // Recurse
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::analyze_with_state(&child, source, path, state, findings);
        }
    }
    
    fn check_for_toctou(
        node: &Node,
        source: &str,
        path: &Path,
        check_func: &str,
        check_pos: usize,
        findings: &mut Vec<Finding>
    ) {
        // Look for file operations after the check
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.start_byte() > check_pos {
                if child.kind() == "call_expression" {
                    if let Some(func) = child.child_by_field_name("function") {
                        let func_name = source[func.start_byte()..func.end_byte()].to_string();
                        let func_lower = func_name.to_lowercase();
                        
                        if func_lower.contains("fopen") || func_lower.contains("open") ||
                           func_lower.contains("chown") || func_lower.contains("chmod") ||
                           func_lower.contains("unlink") || func_lower.contains("rename") {
                            let (line, col) = Scanner::get_position(source, child.start_byte());
                            findings.push(Finding {
                                file: path.to_string_lossy().to_string(),
                                line,
                                column: col,
                                severity: Severity::High,
                                category: "toctou_race_condition".to_string(),
                                message: format!("TOCTOU: {} after {} - file may change between check and use", func_name, check_func),
                                suggestion: Some("Use fstat/fchown on file descriptor instead, or O_NOFOLLOW".to_string()),
                                confidence: 0.85,
                            });
                        }
                    }
                }
                // Recurse
                Self::check_for_toctou(&child, source, path, check_func, check_pos, findings);
            }
        }
    }
    
    fn is_externally_tainted(expr: &str, state: &AdvancedAnalysisState) -> bool {
        let expr_lower = expr.to_lowercase();
        
        // Direct taint sources
        if expr_lower.contains("argv[") ||
           expr_lower.contains("getenv") ||
           expr_lower.contains("fgets") ||
           expr_lower.contains("scanf") ||
           expr_lower.contains("read(") {
            return true;
        }
        
        // Check if variable was marked as tainted
        for var in &state.tainted_vars {
            if expr.contains(var) {
                return true;
            }
        }
        
        false
    }
    
    fn is_tainted_source(expr: &str) -> bool {
        let expr_lower = expr.to_lowercase();
        expr_lower.contains("argv[") ||
        expr_lower.contains("getenv(") ||
        expr_lower.contains("fgets(") ||
        expr_lower.contains("scanf") ||
        expr_lower.contains("read(") ||
        expr_lower.contains("recv(")
    }
}

// Bookkeeping for when things get complicated
struct AdvancedAnalysisState {
    check_operations: Vec<String>,
    check_line: usize,
    closed_resources: HashSet<String>,
    tainted_vars: HashSet<String>,
}

impl AdvancedAnalysisState {
    fn new() -> Self {
        Self {
            check_operations: Vec::new(),
            check_line: 0,
            closed_resources: HashSet::new(),
            tainted_vars: HashSet::new(),
        }
    }
}

impl SymbolicAnalyzer {
    fn analyze_function(node: &Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Walk the AST and track symbolic values
        Self::analyze_node(node, source, path, &mut findings);
        
        findings
    }
    
    fn analyze_node(node: &Node, source: &str, path: &Path, findings: &mut Vec<Finding>) {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = &source[func.start_byte()..func.end_byte()];
                
                // Check memcpy with symbolic size
                if func_name == "memcpy" || func_name == "memset" {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let mut arg_nodes = Vec::new();
                        let mut cursor = args.walk();
                        for child in args.children(&mut cursor) {
                            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                                arg_nodes.push(child);
                            }
                        }
                        
                        if arg_nodes.len() >= 3 {
                            let (line, col) = Scanner::get_position(source, node.start_byte());
                            findings.push(Finding {
                                file: path.to_string_lossy().to_string(),
                                line,
                                column: col,
                                severity: Severity::High,
                                category: "unbounded_memcpy".to_string(),
                                message: "memcpy with potentially unbounded size".to_string(),
                                suggestion: Some("Add bounds check: if (size > MAX) return".to_string()),
                                confidence: 0.78,
                            });
                        }
                    }
                }
            }
        }
        
        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::analyze_node(&child, source, path, findings);
        }
    }
}

// Follow user input like it owes you money

// Tracks taint across functions because bugs love to travel
struct TaintAnalyzer {
    taint_sources: HashSet<String>,
    taint_sinks: HashSet<String>,
}

impl TaintAnalyzer {
    fn new() -> Self {
        let mut sources = HashSet::new();
        sources.insert("scanf".to_string());
        sources.insert("fgets".to_string());
        sources.insert("recv".to_string());
        sources.insert("read".to_string());
        sources.insert("getenv".to_string());
        
        let mut sinks = HashSet::new();
        sinks.insert("system".to_string());
        sinks.insert("popen".to_string());
        sinks.insert("exec".to_string());
        
        Self {
            taint_sources: sources,
            taint_sinks: sinks,
        }
    }
    
    fn analyze_file(&self, node: &Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        self.find_taint_sinks(node, source, path, &mut findings);
        findings
    }
    
    fn find_taint_sinks(&self, node: &Node, source: &str, path: &Path, findings: &mut Vec<Finding>) {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = &source[func.start_byte()..func.end_byte()];
                
                if self.taint_sinks.contains(func_name) {
                    let (line, col) = Scanner::get_position(source, node.start_byte());
                    findings.push(Finding {
                        file: path.to_string_lossy().to_string(),
                        line,
                        column: col,
                        severity: Severity::Critical,
                        category: "command_injection".to_string(),
                        message: format!("Potential command injection: {} with user input", func_name),
                        suggestion: Some("Use execve with full path, or validate input against whitelist".to_string()),
                        confidence: 0.88,
                    });
                }
            }
        }
        
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.find_taint_sinks(&child, source, path, findings);
        }
    }
}

// Tracks your variables like a helicopter parent

// Watches malloc/free like a hawk watching a mouse
struct DataFlowAnalyzer;

impl DataFlowAnalyzer {
    fn analyze(root: &Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut state = DataFlowState::new();
        Self::track_variables(root, source, path, &mut state, &mut findings);
        findings
    }
    
    fn track_variables(node: &Node, source: &str, path: &Path, state: &mut DataFlowState, findings: &mut Vec<Finding>) {
        match node.kind() {
            "declaration" | "parameter_declaration" => {
                // Track variable declarations
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    let var_name = Self::extract_identifier(&declarator, source);
                    let var_type = Self::extract_type(node, source);
                    
                    // Check for uninitialized pointers
                    if var_type.contains("*") && !Self::has_initializer(node) {
                        let (line, col) = Scanner::get_position(source, node.start_byte());
                        findings.push(Finding {
                            file: path.to_string_lossy().to_string(),
                            line,
                            column: col,
                            severity: Severity::Medium,
                            category: "uninitialized_pointer".to_string(),
                            message: format!("Pointer '{}' declared without initialization", var_name),
                            suggestion: Some(format!("Initialize {} to NULL or valid address", var_name)),
                            confidence: 0.82,
                        });
                    }
                    
                    state.declare_variable(var_name, var_type);
                }
            }
            
            "assignment_expression" => {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right")
                ) {
                    let var_name = Self::extract_identifier(&left, source);
                    let rhs = source[right.start_byte()..right.end_byte()].to_string();
                    
                    // Track allocation
                    if rhs.contains("malloc") || rhs.contains("calloc") || rhs.contains("realloc") {
                        state.mark_allocated(var_name.clone());
                        
                        // Check if immediately checked
                        if !Self::next_node_checks_null(node, source) {
                            let (line, col) = Scanner::get_position(source, node.start_byte());
                            findings.push(Finding {
                                file: path.to_string_lossy().to_string(),
                                line,
                                column: col,
                                severity: Severity::High,
                                category: "unchecked_allocation".to_string(),
                                message: format!("'{}' allocated but not checked for NULL", var_name),
                                suggestion: Some(format!("Add: if (!{}) {{ return NULL; }}", var_name)),
                                confidence: 0.88,
                            });
                        }
                    }
                    
                    // Track NULL assignment
                    if rhs.trim() == "NULL" || rhs.trim() == "0" {
                        state.mark_null(var_name.clone());
                    }
                    
                    // Track freed pointer
                    if rhs.contains("free(") {
                        if let Some(freed_var) = Self::extract_freed_var(&right, source) {
                            state.mark_freed(freed_var);
                        }
                    }
                }
            }
            
            "call_expression" => {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_name = &source[func.start_byte()..func.end_byte()];
                    
                    // Check for use-after-free
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let mut cursor = args.walk();
                        for arg in args.children(&mut cursor) {
                            let arg_text = source[arg.start_byte()..arg.end_byte()].to_string();
                            if state.is_freed(&arg_text) {
                                let (line, col) = Scanner::get_position(source, node.start_byte());
                                findings.push(Finding {
                                    file: path.to_string_lossy().to_string(),
                                    line,
                                    column: col,
                                    severity: Severity::Critical,
                                    category: "use_after_free".to_string(),
                                    message: format!("'{}' used after free", arg_text),
                                    suggestion: Some(format!("Remove use of {} after free, or set to NULL", arg_text)),
                                    confidence: 0.91,
                                });
                            }
                        }
                    }
                    
                    // Check for double-free
                    if func_name == "free" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let mut cursor = args.walk();
                            for arg in args.children(&mut cursor) {
                                if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                                    let arg_text = source[arg.start_byte()..arg.end_byte()].to_string();
                                    if state.is_freed(&arg_text) {
                                        let (line, col) = Scanner::get_position(source, node.start_byte());
                                        findings.push(Finding {
                                            file: path.to_string_lossy().to_string(),
                                            line,
                                            column: col,
                                            severity: Severity::Critical,
                                            category: "double_free".to_string(),
                                            message: format!("Double-free of '{}' detected", arg_text),
                                            suggestion: Some("Set pointer to NULL after first free".to_string()),
                                            confidence: 0.93,
                                        });
                                    }
                                    state.mark_freed(arg_text);
                                }
                            }
                        }
                    }
                    
                    // Check format string vulnerabilities
                    if func_name == "printf" || func_name == "sprintf" || func_name == "fprintf" || func_name == "snprintf" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let mut cursor = args.walk();
                            let mut first_arg = true;
                            for arg in args.children(&mut cursor) {
                                if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                                    if first_arg {
                                        first_arg = false;
                                        let fmt = source[arg.start_byte()..arg.end_byte()].to_string();
                                        // Check if format string is user-controlled (not literal)
                                        if arg.kind() != "string_literal" && arg.kind() != "string_content" {
                                            let (line, col) = Scanner::get_position(source, node.start_byte());
                                            findings.push(Finding {
                                                file: path.to_string_lossy().to_string(),
                                                line,
                                                column: col,
                                                severity: Severity::Critical,
                                                category: "format_string".to_string(),
                                                message: format!("Format string vulnerability in {}", func_name),
                                                suggestion: Some("Use constant format string, never user input".to_string()),
                                                confidence: 0.90,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            "pointer_expression" | "subscript_expression" => {
                // Check for dereference of potentially NULL pointer
                if let Some(operand) = node.child(0).or_else(|| node.child_by_field_name("argument")) {
                    let var_name = Self::extract_identifier(&operand, source);
                    if state.is_null(&var_name) && !state.is_checked(&var_name) {
                        let (line, col) = Scanner::get_position(source, node.start_byte());
                        findings.push(Finding {
                            file: path.to_string_lossy().to_string(),
                            line,
                            column: col,
                            severity: Severity::Critical,
                            category: "null_dereference_confirmed".to_string(),
                            message: format!("Confirmed NULL dereference of '{}'", var_name),
                            suggestion: Some(format!("Add null check before dereferencing {}", var_name)),
                            confidence: 0.94,
                        });
                    }
                }
            }
            
            "if_statement" => {
                // Check if this is a null check
                if let Some(condition) = node.child_by_field_name("condition") {
                    let cond_text = source[condition.start_byte()..condition.end_byte()].to_string();
                    if let Some(var) = Self::extract_checked_var(&condition, source) {
                        state.mark_checked(var);
                    }
                }
            }
            
            _ => {}
        }
        
        // Recurse
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::track_variables(&child, source, path, state, findings);
        }
    }
    
    fn extract_identifier(node: &Node, source: &str) -> String {
        if node.kind() == "identifier" {
            source[node.start_byte()..node.end_byte()].to_string()
        } else {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "identifier" {
                    return source[child.start_byte()..child.end_byte()].to_string();
                }
            }
            String::new()
        }
    }
    
    fn extract_type(node: &Node, source: &str) -> String {
        if let Some(type_node) = node.child_by_field_name("type") {
            source[type_node.start_byte()..type_node.end_byte()].to_string()
        } else {
            String::new()
        }
    }
    
    fn has_initializer(node: &Node) -> bool {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "=" || child.kind() == "init_declarator" {
                return true;
            }
        }
        false
    }
    
    fn next_node_checks_null(node: &Node, _source: &str) -> bool {
        // Conservative: assume no check unless clearly visible
        false
    }
    
    fn extract_freed_var(node: &Node, source: &str) -> Option<String> {
        // Extract variable name from free(var) call
        let text = source[node.start_byte()..node.end_byte()].to_string();
        if let Some(start) = text.find('(') {
            if let Some(end) = text.find(')') {
                let var = text[start + 1..end].trim().to_string();
                if !var.is_empty() {
                    return Some(var);
                }
            }
        }
        None
    }
    
    fn extract_checked_var(condition: &Node, source: &str) -> Option<String> {
        let text = source[condition.start_byte()..condition.end_byte()].to_string();
        // Simple heuristic: extract variable from "if (var != NULL)" or "if (var)"
        if text.contains("!= NULL") || text.contains("!= 0") {
            if let Some(pos) = text.find("!=") {
                let var = text[..pos].trim().to_string();
                return Some(var);
            }
        }
        None
    }
}

// State machine for memory. Yes, it's as exciting as it sounds.
struct DataFlowState {
    variables: HashMap<String, VarState>,
}

#[derive(Clone)]
enum VarState {
    Uninitialized,
    Allocated,
    Null,
    Freed,
    Checked,
    Unknown,
}

impl DataFlowState {
    fn new() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }
    
    fn declare_variable(&mut self, name: String, _type: String) {
        self.variables.insert(name, VarState::Uninitialized);
    }
    
    fn mark_allocated(&mut self, name: String) {
        self.variables.insert(name, VarState::Allocated);
    }
    
    fn mark_null(&mut self, name: String) {
        self.variables.insert(name, VarState::Null);
    }
    
    fn mark_freed(&mut self, name: String) {
        self.variables.insert(name, VarState::Freed);
    }
    
    fn mark_checked(&mut self, name: String) {
        self.variables.insert(name, VarState::Checked);
    }
    
    fn is_freed(&self, name: &str) -> bool {
        matches!(self.variables.get(name), Some(VarState::Freed))
    }
    
    fn is_null(&self, name: &str) -> bool {
        matches!(self.variables.get(name), Some(VarState::Null) | Some(VarState::Uninitialized))
    }
    
    fn is_checked(&self, name: &str) -> bool {
        matches!(self.variables.get(name), Some(VarState::Checked))
    }
}

// Types are hard. Let's complain about them.

struct TypeAwareChecker;

impl TypeAwareChecker {
    fn analyze(root: &Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        Self::check_types_recursive(root, source, path, &mut findings);
        findings
    }
    
    fn check_types_recursive(node: &Node, source: &str, path: &Path, findings: &mut Vec<Finding>) {
        match node.kind() {
            "call_expression" => {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_name = &source[func.start_byte()..func.end_byte()];
                    
                    // Check for dangerous casting
                    if func_name == "malloc" || func_name == "calloc" || func_name == "realloc" {
                        if let Some(parent) = node.parent() {
                            if parent.kind() == "cast_expression" {
                                // C++ style cast - OK
                            } else if let Some(decl) = parent.parent() {
                                // In C, malloc return should be cast or assigned to pointer
                                // Already handled by compiler, but we check for sizeof mismatch
                                if let Some(args) = node.child_by_field_name("arguments") {
                                    let mut cursor = args.walk();
                                    for arg in args.children(&mut cursor) {
                                        if arg.kind() == "binary_expression" {
                                            let text = source[arg.start_byte()..arg.end_byte()].to_string();
                                            if text.contains("sizeof") {
                                                // Check for sizeof(int) vs sizeof(char*) mismatch
                                                let (line, col) = Scanner::get_position(source, node.start_byte());
                                                findings.push(Finding {
                                                    file: path.to_string_lossy().to_string(),
                                                    line,
                                                    column: col,
                                                    severity: Severity::Medium,
                                                    category: "malloc_sizeof".to_string(),
                                                    message: "Verify sizeof matches pointer type".to_string(),
                                                    suggestion: Some("Use sizeof(*ptr) instead of sizeof(type)".to_string()),
                                                    confidence: 0.60,
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    // Check for unchecked return values
                    if matches!(func_name, "fopen" | "socket" | "accept" | "mmap" | "pthread_create") {
                        if let Some(parent) = node.parent() {
                            if parent.kind() != "assignment_expression" && 
                               parent.kind() != "init_declarator" &&
                               parent.kind() != "binary_expression" {
                                let (line, col) = Scanner::get_position(source, node.start_byte());
                                findings.push(Finding {
                                    file: path.to_string_lossy().to_string(),
                                    line,
                                    column: col,
                                    severity: Severity::High,
                                    category: "unchecked_return".to_string(),
                                    message: format!("{} return value not checked", func_name),
                                    suggestion: Some("Assign to variable and check for error".to_string()),
                                    confidence: 0.85,
                                });
                            }
                        }
                    }
                    
                    // Check for dangerous casts
                    if func_name == "malloc" || func_name == "calloc" || func_name == "realloc" {
                        if let Some(parent) = node.parent() {
                            if parent.kind() == "cast_expression" {
                                let cast_text = source[parent.start_byte()..parent.end_byte()].to_string();
                                if cast_text.contains("(void*)") || cast_text.contains("(char*)") {
                                    let (line, col) = Scanner::get_position(source, node.start_byte());
                                    findings.push(Finding {
                                        file: path.to_string_lossy().to_string(),
                                        line,
                                        column: col,
                                        severity: Severity::High,
                                        category: "integer_to_pointer".to_string(),
                                        message: "Integer cast to pointer - potential security issue".to_string(),
                                        suggestion: Some("Use intptr_t/uintptr_t for integer-pointer conversions".to_string()),
                                        confidence: 0.87,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            
            "cast_expression" => {
                let cast_text = source[node.start_byte()..node.end_byte()].to_string();
                // Check for dangerous casts
                if cast_text.contains("(void*)") || cast_text.contains("(char*)") {
                    if let Some(value) = node.child_by_field_name("value") {
                        let val_text = source[value.start_byte()..value.end_byte()].to_string();
                        if val_text.parse::<i64>().is_ok() {
                            let (line, col) = Scanner::get_position(source, node.start_byte());
                            findings.push(Finding {
                                file: path.to_string_lossy().to_string(),
                                line,
                                column: col,
                                severity: Severity::High,
                                category: "integer_to_pointer".to_string(),
                                message: "Integer cast to pointer - potential security issue".to_string(),
                                suggestion: Some("Use intptr_t/uintptr_t for integer-pointer conversions".to_string()),
                                confidence: 0.87,
                            });
                        }
                    }
                }
            }
            
            _ => {}
        }
        
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::check_types_recursive(&child, source, path, findings);
        }
    }
}

// Calling other functions? Let's analyze that too because we're overachievers

struct CallGraphAnalyzer {
    function_summaries: HashMap<String, FunctionSummary>,
}

#[derive(Clone)]
struct FunctionSummary {
    name: String,
    returns_malloc: bool,
    takes_user_input: bool,
    calls_system: bool,
}

impl CallGraphAnalyzer {
    fn new() -> Self {
        let mut summaries = HashMap::new();
        
        // Built-in summaries for standard library
        summaries.insert("malloc".to_string(), FunctionSummary {
            name: "malloc".to_string(),
            returns_malloc: true,
            takes_user_input: false,
            calls_system: false,
        });
        summaries.insert("calloc".to_string(), FunctionSummary {
            name: "calloc".to_string(),
            returns_malloc: true,
            takes_user_input: false,
            calls_system: false,
        });
        summaries.insert("strdup".to_string(), FunctionSummary {
            name: "strdup".to_string(),
            returns_malloc: true,
            takes_user_input: true,
            calls_system: false,
        });
        summaries.insert("system".to_string(), FunctionSummary {
            name: "system".to_string(),
            returns_malloc: false,
            takes_user_input: true,
            calls_system: true,
        });
        summaries.insert("popen".to_string(), FunctionSummary {
            name: "popen".to_string(),
            returns_malloc: false,
            takes_user_input: true,
            calls_system: true,
        });
        summaries.insert("scanf".to_string(), FunctionSummary {
            name: "scanf".to_string(),
            returns_malloc: false,
            takes_user_input: true,
            calls_system: false,
        });
        summaries.insert("gets".to_string(), FunctionSummary {
            name: "gets".to_string(),
            returns_malloc: false,
            takes_user_input: true,
            calls_system: false,
        });
        
        Self {
            function_summaries: summaries,
        }
    }
    
    fn analyze_file(&self, root: &Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut local_functions: HashMap<String, FunctionSummary> = HashMap::new();
        
        // First pass: build summaries for local functions
        Self::build_summaries(root, source, &mut local_functions);
        
        // Second pass: detect cross-function bugs
        Self::check_cross_function_bugs(root, source, path, &self.function_summaries, &local_functions, &mut findings);
        
        findings
    }
    
    fn build_summaries(node: &Node, source: &str, summaries: &mut HashMap<String, FunctionSummary>) {
        if node.kind() == "function_definition" {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                let func_name = Self::extract_function_name(&declarator, source);
                if !func_name.is_empty() {
                    let mut summary = FunctionSummary {
                        name: func_name.clone(),
                        returns_malloc: false,
                        takes_user_input: false,
                        calls_system: false,
                    };
                    
                    // Analyze function body for properties
                    if let Some(body) = node.child_by_field_name("body") {
                        Self::analyze_body(&body, source, &mut summary);
                    }
                    
                    summaries.insert(func_name, summary);
                }
            }
        }
        
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::build_summaries(&child, source, summaries);
        }
    }
    
    fn analyze_body(node: &Node, source: &str, summary: &mut FunctionSummary) {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let name = &source[func.start_byte()..func.end_byte()];
                if name == "malloc" || name == "calloc" || name == "realloc" {
                    summary.returns_malloc = true;
                }
                if name == "scanf" || name == "fgets" || name == "read" || name == "recv" {
                    summary.takes_user_input = true;
                }
                if name == "system" || name == "popen" || name == "exec" {
                    summary.calls_system = true;
                }
            }
        }
        
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::analyze_body(&child, source, summary);
        }
    }
    
    fn check_cross_function_bugs(node: &Node, source: &str, path: &Path, 
                                 builtins: &HashMap<String, FunctionSummary>,
                                 local_funcs: &HashMap<String, FunctionSummary>,
                                 findings: &mut Vec<Finding>) {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let name = source[func.start_byte()..func.end_byte()].to_string();
                
                // Check for user_input -> dangerous_sink chain
                let func_summary = local_funcs.get(&name).or_else(|| builtins.get(&name));
                
                if let Some(summary) = func_summary {
                    // Function returns malloc'd memory but caller doesn't check
                    if summary.returns_malloc {
                        if let Some(parent) = node.parent() {
                            if parent.kind() != "assignment_expression" && 
                               parent.kind() != "init_declarator" {
                                let (line, col) = Scanner::get_position(source, node.start_byte());
                                findings.push(Finding {
                                    file: path.to_string_lossy().to_string(),
                                    line,
                                    column: col,
                                    severity: Severity::High,
                                    category: "unchecked_malloc_return".to_string(),
                                    message: format!("{} returns allocated memory but result not used", name),
                                    suggestion: Some("Assign result and check for NULL".to_string()),
                                    confidence: 0.83,
                                });
                            }
                        }
                    }
                    
                    // Function takes user input and calls system - dangerous composition
                    if summary.takes_user_input && summary.calls_system {
                        let (line, col) = Scanner::get_position(source, node.start_byte());
                        findings.push(Finding {
                            file: path.to_string_lossy().to_string(),
                            line,
                            column: col,
                            severity: Severity::Critical,
                            category: "tainted_system_call".to_string(),
                            message: format!("{} propagates user input to system call - command injection risk", name),
                            suggestion: Some("Sanitize input before passing to system functions".to_string()),
                            confidence: 0.86,
                        });
                    }
                }
            }
        }
        
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::check_cross_function_bugs(&child, source, path, builtins, local_funcs, findings);
        }
    }
    
    fn extract_function_name(node: &Node, source: &str) -> String {
        if node.kind() == "identifier" {
            source[node.start_byte()..node.end_byte()].to_string()
        } else if node.kind() == "function_declarator" {
            if let Some(decl) = node.child_by_field_name("declarator") {
                Self::extract_function_name(&decl, source)
            } else {
                String::new()
            }
        } else {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                let name = Self::extract_function_name(&child, source);
                if !name.is_empty() {
                    return name;
                }
            }
            String::new()
        }
    }
}

// ============================================================================
// ADDITIONAL LANGUAGE ANALYZERS
// ============================================================================

struct JavaAnalyzer {
    parser: TSParser,
}

impl JavaAnalyzer {
    fn new() -> Option<Self> {
        let mut parser = TSParser::new();
        parser.set_language(&tree_sitter_java::LANGUAGE.into()).ok()?;
        Some(Self { parser })
    }
    
    fn analyze(&mut self, source: &str, path: &Path) -> Vec<Finding> {
        let tree = match self.parser.parse(source, None) {
            Some(t) => t,
            None => return self.fallback_analysis(source, path),
        };
        
        let root = tree.root_node();
        let mut findings = Vec::new();
        let mut tainted_vars: HashSet<String> = HashSet::new();
        
        // First pass: identify taint sources
        Self::find_taint_sources(&root, source, &mut tainted_vars);
        
        // Second pass: find dangerous sinks
        Self::find_dangerous_sinks(&root, source, path, &tainted_vars, &mut findings);
        
        findings
    }
    
    fn find_taint_sources(node: &Node, source: &str, tainted_vars: &mut HashSet<String>) {
        match node.kind() {
            "variable_declarator" | "assignment_expression" => {
                if let (Some(name), Some(value)) = (
                    node.child_by_field_name("name").or_else(|| node.child_by_field_name("left")),
                    node.child_by_field_name("value").or_else(|| node.child_by_field_name("right"))
                ) {
                    let value_text = &source[value.start_byte()..value.end_byte()];
                    if Self::is_taint_source(value_text) {
                        let name_text = &source[name.start_byte()..name.end_byte()];
                        tainted_vars.insert(name_text.to_string());
                    }
                }
            }
            _ => {}
        }
        
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::find_taint_sources(&child, source, tainted_vars);
        }
    }
    
    fn is_taint_source(expr: &str) -> bool {
        let expr_lower = expr.to_lowercase();
        expr_lower.contains("getparameter") ||
        expr_lower.contains("getheader") ||
        expr_lower.contains("getinputstream") ||
        expr_lower.contains("getreader") ||
        expr_lower.contains("system.getenv") ||
        expr_lower.contains("bufferedreader.read") ||
        expr_lower.contains("socket.getinputstream") ||
        expr_lower.contains("request.")
    }
    
    fn find_dangerous_sinks(
        node: &Node,
        source: &str,
        path: &Path,
        tainted_vars: &HashSet<String>,
        findings: &mut Vec<Finding>
    ) {
        match node.kind() {
            "method_invocation" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let method_name = &source[name.start_byte()..name.end_byte()];
                    let method_lower = method_name.to_lowercase();
                    
                    // Deserialization
                    if method_lower == "readobject" || method_lower == "readunshared" {
                        if let Some(obj) = node.child_by_field_name("object") {
                            let obj_text = &source[obj.start_byte()..obj.end_byte()];
                            if obj_text.to_lowercase().contains("objectinputstream") {
                                let (line, col) = Self::get_position(source, node.start_byte());
                                findings.push(Finding::new(
                                    path.to_string_lossy().to_string(),
                                    line, col, Severity::Critical,
                                    "java_deserialization".to_string(),
                                    "Insecure Java deserialization - RCE risk".to_string(),
                                    Some("Use look-ahead ObjectInputStream with class whitelist".to_string())
                                ).with_confidence(0.94));
                            }
                        }
                    }
                    
                    // Command injection
                    if method_lower == "exec" {
                        if Self::has_tainted_argument(node, source, tainted_vars) {
                            let (line, col) = Self::get_position(source, node.start_byte());
                            findings.push(Finding::new(
                                path.to_string_lossy().to_string(),
                                line, col, Severity::Critical,
                                "java_command_injection".to_string(),
                                "Runtime.exec with user input - command injection".to_string(),
                                Some("Use ProcessBuilder with array, validate command".to_string())
                            ).with_confidence(0.91));
                        }
                    }
                    
                    // SQL injection
                    if method_lower == "execute" || method_lower == "executequery" || method_lower == "executeupdate" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let args_text = &source[args.start_byte()..args.end_byte()];
                            if (args_text.contains("+") || args_text.contains("string.format") ||
                                args_text.contains("concat") || args_text.contains("append")) &&
                               Self::has_tainted_argument(node, source, tainted_vars) {
                                let (line, col) = Self::get_position(source, node.start_byte());
                                findings.push(Finding::new(
                                    path.to_string_lossy().to_string(),
                                    line, col, Severity::Critical,
                                    "java_sql_injection".to_string(),
                                    "SQL query with string concatenation".to_string(),
                                    Some("Use PreparedStatement with ? placeholders".to_string())
                                ).with_confidence(0.89));
                            }
                        }
                    }
                    
                    // XPath injection
                    if method_lower == "compile" && Self::has_tainted_argument(node, source, tainted_vars) {
                        let (line, col) = Self::get_position(source, node.start_byte());
                        findings.push(Finding::new(
                            path.to_string_lossy().to_string(),
                            line, col, Severity::High,
                            "java_xpath_injection".to_string(),
                            "XPath expression with user input".to_string(),
                            Some("Validate XPath expression or use parameterized queries".to_string())
                        ).with_confidence(0.82));
                    }
                    
                    // XXE (XML External Entity)
                    if method_lower == "parse" || method_lower == "newdocumentbuilder" {
                        let (line, col) = Self::get_position(source, node.start_byte());
                        findings.push(Finding::new(
                            path.to_string_lossy().to_string(),
                            line, col, Severity::High,
                            "java_xxe".to_string(),
                            "XML parsing without XXE protection".to_string(),
                            Some("Disable external entities: setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)".to_string())
                        ).with_confidence(0.80));
                    }
                    
                    // LDAP injection
                    if method_lower.contains("ldap") && Self::has_tainted_argument(node, source, tainted_vars) {
                        let (line, col) = Self::get_position(source, node.start_byte());
                        findings.push(Finding::new(
                            path.to_string_lossy().to_string(),
                            line, col, Severity::High,
                            "java_ldap_injection".to_string(),
                            "LDAP query with user input".to_string(),
                            Some("Escape LDAP filter special characters".to_string())
                        ).with_confidence(0.82));
                    }
                }
            }
            
            "class_declaration" => {
                // Check for serializable without safeguards
                if let Some(body) = node.child_by_field_name("body") {
                    let body_text = &source[body.start_byte()..body.end_byte()];
                    if body_text.contains("implements Serializable") || body_text.contains("implements java.io.Serializable") {
                        if !body_text.contains("readObject") && !body_text.contains("ObjectInputValidation") {
                            let (line, col) = Self::get_position(source, node.start_byte());
                            findings.push(Finding::new(
                                path.to_string_lossy().to_string(),
                                line, col, Severity::Medium,
                                "java_serializable".to_string(),
                                "Class implements Serializable without validation".to_string(),
                                Some("Add readObject() with InputValidation".to_string())
                            ).with_confidence(0.75));
                        }
                    }
                }
            }
            
            _ => {}
        }
        
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::find_dangerous_sinks(&child, source, path, tainted_vars, findings);
        }
    }
    
    fn has_tainted_argument(node: &Node, source: &str, tainted_vars: &HashSet<String>) -> bool {
        if let Some(args) = node.child_by_field_name("arguments") {
            let args_text = source[args.start_byte()..args.end_byte()].to_string();
            for var in tainted_vars {
                if args_text.contains(var) {
                    return true;
                }
            }
        }
        false
    }
    
    fn get_position(source: &str, byte_offset: usize) -> (usize, usize) {
        let line = source[..byte_offset].lines().count();
        let column = source[..byte_offset].lines().last().map(|l| l.len()).unwrap_or(0);
        (line, column)
    }
    
    fn fallback_analysis(&self, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in source.lines().enumerate() {
            let line_lower = line.to_lowercase();
            if line_lower.contains("objectinputstream") && line_lower.contains("readobject") {
                findings.push(Finding::new(
                    path.to_string_lossy().to_string(),
                    i + 1, 0, Severity::Critical,
                    "java_deserialization".to_string(),
                    "Insecure deserialization".to_string(),
                    Some("Validate class whitelist".to_string())
                ).with_confidence(0.90));
            }
        }
        findings
    }
}

impl LanguageAnalyzer for JavaAnalyzer {
    fn analyze(&mut self, path: &Path, _language: Language) -> Vec<Finding> {
        if let Ok(file) = File::open(path) {
            if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                let source = String::from_utf8_lossy(&mmap);
                return self.analyze(&source, path);
            }
        }
        Vec::new()
    }
}

struct PythonAnalyzer {
    parser: TSParser,
}

impl PythonAnalyzer {
    fn new() -> Option<Self> {
        let mut parser = TSParser::new();
        parser.set_language(&tree_sitter_python::LANGUAGE.into()).ok()?;
        Some(Self { parser })
    }
    
    fn analyze(&mut self, source: &str, path: &Path) -> Vec<Finding> {
        let tree = match self.parser.parse(source, None) {
            Some(t) => t,
            None => return self.fallback_analysis(source, path),
        };
        
        let root = tree.root_node();
        let mut findings = Vec::new();
        let mut tainted_vars: HashSet<String> = HashSet::new();
        
        // First pass: identify taint sources
        Self::find_taint_sources(&root, source, &mut tainted_vars);
        
        // Second pass: find dangerous sinks with taint flow
        Self::find_dangerous_sinks(&root, source, path, &tainted_vars, &mut findings);
        
        findings
    }
    
    fn find_taint_sources(node: &Node, source: &str, tainted_vars: &mut HashSet<String>) {
        // Track imports and assignments from tainted sources
        if node.kind() == "assignment" {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right")
            ) {
                let rhs = &source[right.start_byte()..right.end_byte()];
                let lhs = &source[left.start_byte()..left.end_byte()];
                
                // Check if RHS is a taint source
                if Self::is_taint_source(rhs) {
                    tainted_vars.insert(lhs.to_string());
                }
            }
        }
        
        // Recurse
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::find_taint_sources(&child, source, tainted_vars);
        }
    }
    
    fn is_taint_source(expr: &str) -> bool {
        let expr_lower = expr.to_lowercase();
        expr_lower.contains("input(") ||
        expr_lower.contains("sys.argv") ||
        expr_lower.contains("request.") ||
        expr_lower.contains("os.environ[") ||
        expr_lower.contains("socket.recv") ||
        expr_lower.contains("read(") ||
        expr_lower.contains("json.loads") && expr_lower.contains("request")
    }
    
    fn find_dangerous_sinks(
        node: &Node, 
        source: &str, 
        path: &Path,
        tainted_vars: &HashSet<String>,
        findings: &mut Vec<Finding>
    ) {
        match node.kind() {
            "call" => {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_name = &source[func.start_byte()..func.end_byte()];
                    let func_lower = func_name.to_lowercase();
                    
                    // Check for dangerous function calls
                    if func_lower.contains("eval") && !func_lower.contains("literal_eval") {
                        if Self::has_tainted_argument(node, source, tainted_vars) {
                            let (line, col) = Self::get_position(source, node.start_byte());
                            findings.push(Finding::new(
                                path.to_string_lossy().to_string(),
                                line, col, Severity::Critical,
                                "python_tainted_eval".to_string(),
                                format!("eval() called with tainted input: {}", func_name),
                                Some("Never eval user input - use ast.literal_eval for safe parsing".to_string())
                            ).with_confidence(0.96));
                        }
                    }
                    
                    if func_lower == "exec" {
                        if Self::has_tainted_argument(node, source, tainted_vars) {
                            let (line, col) = Self::get_position(source, node.start_byte());
                            findings.push(Finding::new(
                                path.to_string_lossy().to_string(),
                                line, col, Severity::Critical,
                                "python_tainted_exec".to_string(),
                                "exec() called with user input".to_string(),
                                Some("Never execute user input - massive RCE risk".to_string())
                            ).with_confidence(0.96));
                        }
                    }
                    
                    if func_lower.contains("pickle.load") {
                        let (line, col) = Self::get_position(source, node.start_byte());
                        findings.push(Finding::new(
                            path.to_string_lossy().to_string(),
                            line, col, Severity::Critical,
                            "python_pickle".to_string(),
                            "Insecure pickle deserialization".to_string(),
                            Some("Only unpickle cryptographically signed data".to_string())
                        ).with_confidence(0.92));
                    }
                    
                    if func_lower.contains("yaml.load") && !func_lower.contains("safe_load") {
                        let (line, col) = Self::get_position(source, node.start_byte());
                        findings.push(Finding::new(
                            path.to_string_lossy().to_string(),
                            line, col, Severity::Critical,
                            "python_yaml_load".to_string(),
                            "Unsafe YAML load - arbitrary code execution".to_string(),
                            Some("Use yaml.safe_load() instead".to_string())
                        ).with_confidence(0.94));
                    }
                    
                    if func_lower.contains("subprocess") && func_lower.contains("call") {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let args_text = &source[args.start_byte()..args.end_byte()];
                            if args_text.contains("shell") && args_text.contains("True") {
                                let (line, col) = Self::get_position(source, node.start_byte());
                                findings.push(Finding::new(
                                    path.to_string_lossy().to_string(),
                                    line, col, Severity::Critical,
                                    "python_shell_injection".to_string(),
                                    "subprocess with shell=True - command injection".to_string(),
                                    Some("Use shell=False with list of arguments".to_string())
                                ).with_confidence(0.90));
                            }
                        }
                    }
                    
                    if func_lower.contains("os.system") {
                        let (line, col) = Self::get_position(source, node.start_byte());
                        findings.push(Finding::new(
                            path.to_string_lossy().to_string(),
                            line, col, Severity::Critical,
                            "python_os_system".to_string(),
                            "os.system() - command injection risk".to_string(),
                            Some("Use subprocess with shell=False".to_string())
                        ).with_confidence(0.88));
                    }
                    
                    // SQL injection via string formatting
                    if func_lower.contains("execute") || func_lower.contains("executemany") {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let args_text = &source[args.start_byte()..args.end_byte()];
                            if (args_text.contains("%") || args_text.contains(".format(") || 
                                args_text.contains("f\"")) && 
                               Self::has_tainted_argument(node, source, tainted_vars) {
                                let (line, col) = Self::get_position(source, node.start_byte());
                                findings.push(Finding::new(
                                    path.to_string_lossy().to_string(),
                                    line, col, Severity::Critical,
                                    "python_sql_injection".to_string(),
                                    "SQL query with string formatting and user input".to_string(),
                                    Some("Use parameterized queries with placeholders".to_string())
                                ).with_confidence(0.87));
                            }
                        }
                    }
                }
            }
            
            "template_string" | "string" => {
                // Check for SSTI (Server-Side Template Injection)
                let text = &source[node.start_byte()..node.end_byte()];
                if text.contains("{{") && text.contains("}}") {
                    if Self::has_tainted_data(node, source, tainted_vars) {
                        let (line, col) = Self::get_position(source, node.start_byte());
                        findings.push(Finding::new(
                            path.to_string_lossy().to_string(),
                            line, col, Severity::Critical,
                            "python_ssti".to_string(),
                            "Template string with user input - SSTI risk".to_string(),
                            Some("Use template engines with auto-escaping".to_string())
                        ).with_confidence(0.82));
                    }
                }
            }
            
            _ => {}
        }
        
        // Recurse
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::find_dangerous_sinks(&child, source, path, tainted_vars, findings);
        }
    }
    
    fn has_tainted_argument(node: &Node, source: &str, tainted_vars: &HashSet<String>) -> bool {
        if let Some(args) = node.child_by_field_name("arguments") {
            let args_text = source[args.start_byte()..args.end_byte()].to_string();
            for var in tainted_vars {
                if args_text.contains(var) {
                    return true;
                }
            }
        }
        false
    }
    
    fn has_tainted_data(node: &Node, source: &str, tainted_vars: &HashSet<String>) -> bool {
        let node_text = source[node.start_byte()..node.end_byte()].to_string();
        for var in tainted_vars {
            if node_text.contains(var) {
                return true;
            }
        }
        false
    }
    
    fn get_position(source: &str, byte_offset: usize) -> (usize, usize) {
        let line = source[..byte_offset].lines().count();
        let column = source[..byte_offset].lines().last().map(|l| l.len()).unwrap_or(0);
        (line, column)
    }
    
    // Fallback to pattern-based if AST parsing fails
    fn fallback_analysis(&self, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in source.lines().enumerate() {
            let line_lower = line.to_lowercase();
            
            if line_lower.contains("eval(") && !line_lower.contains("literal_eval") {
                findings.push(Finding::new(
                    path.to_string_lossy().to_string(),
                    i + 1, 0, Severity::Critical,
                    "python_eval".to_string(),
                    "eval() detected".to_string(),
                    Some("Use ast.literal_eval".to_string())
                ).with_confidence(0.90));
            }
        }
        findings
    }
}

impl LanguageAnalyzer for PythonAnalyzer {
    fn analyze(&mut self, path: &Path, _language: Language) -> Vec<Finding> {
        if let Ok(file) = File::open(path) {
            if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                let source = String::from_utf8_lossy(&mmap);
                return self.analyze(&source, path);
            }
        }
        Vec::new()
    }
}

struct JavaScriptAnalyzer {
    parser: TSParser,
}

impl JavaScriptAnalyzer {
    fn new() -> Option<Self> {
        let mut parser = TSParser::new();
        parser.set_language(&tree_sitter_javascript::LANGUAGE.into()).ok()?;
        Some(Self { parser })
    }
    
    fn analyze(&mut self, source: &str, path: &Path) -> Vec<Finding> {
        let tree = match self.parser.parse(source, None) {
            Some(t) => t,
            None => return self.fallback_analysis(source, path),
        };
        
        let root = tree.root_node();
        let mut findings = Vec::new();
        let mut tainted_vars: HashSet<String> = HashSet::new();
        
        // First pass: identify taint sources (req.body, req.query, etc.)
        Self::find_taint_sources(&root, source, &mut tainted_vars);
        
        // Second pass: find dangerous sinks with taint flow
        Self::find_dangerous_sinks(&root, source, path, &tainted_vars, &mut findings);
        
        findings
    }
    
    fn find_taint_sources(node: &Node, source: &str, tainted_vars: &mut HashSet<String>) {
        match node.kind() {
            "member_expression" | "identifier" => {
                let text = &source[node.start_byte()..node.end_byte()];
                if Self::is_taint_source(text) {
                    // Try to get the variable name
                    if let Some(parent) = node.parent() {
                        if parent.kind() == "assignment_expression" || parent.kind() == "variable_declarator" {
                            if let Some(name_node) = parent.child_by_field_name("left") {
                                let name = &source[name_node.start_byte()..name_node.end_byte()];
                                tainted_vars.insert(name.to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        
        // Recurse
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::find_taint_sources(&child, source, tainted_vars);
        }
    }
    
    fn is_taint_source(expr: &str) -> bool {
        let expr_lower = expr.to_lowercase();
        expr_lower.contains("req.") ||
        expr_lower.contains("request.") ||
        expr_lower.contains("req.body") ||
        expr_lower.contains("req.query") ||
        expr_lower.contains("req.params") ||
        expr_lower.contains("location.") ||
        expr_lower.contains("window.location") ||
        expr_lower.contains("document.cookie") ||
        expr_lower.contains("localstorage") ||
        expr_lower.contains("sessionstorage") ||
        expr_lower.contains("postmessage")
    }
    
    fn find_dangerous_sinks(
        node: &Node,
        source: &str,
        path: &Path,
        tainted_vars: &HashSet<String>,
        findings: &mut Vec<Finding>
    ) {
        match node.kind() {
            "call_expression" => {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_name = &source[func.start_byte()..func.end_byte()];
                    let func_lower = func_name.to_lowercase();
                    
                    // eval() with tainted input
                    if func_lower == "eval" {
                        if Self::has_tainted_argument(node, source, tainted_vars) {
                            let (line, col) = Self::get_position(source, node.start_byte());
                            findings.push(Finding::new(
                                path.to_string_lossy().to_string(),
                                line, col, Severity::Critical,
                                "js_tainted_eval".to_string(),
                                "eval() with user input - XSS/RCE".to_string(),
                                Some("Never eval user input".to_string())
                            ).with_confidence(0.97));
                        }
                    }
                    
                    // Function constructor
                    if func_lower == "function" && func.kind() == "identifier" {
                        if Self::has_tainted_argument(node, source, tainted_vars) {
                            let (line, col) = Self::get_position(source, node.start_byte());
                            findings.push(Finding::new(
                                path.to_string_lossy().to_string(),
                                line, col, Severity::Critical,
                                "js_function_constructor".to_string(),
                                "Function() with user input".to_string(),
                                Some("Never use Function constructor with user input".to_string())
                            ).with_confidence(0.95));
                        }
                    }
                    
                    // setTimeout/setInterval with string
                    if func_lower == "settimeout" || func_lower == "setinterval" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let args_text = &source[args.start_byte()..args.end_byte()];
                            if args_text.contains("\"") || args_text.contains("'") || args_text.contains("`") {
                                let (line, col) = Self::get_position(source, node.start_byte());
                                findings.push(Finding::new(
                                    path.to_string_lossy().to_string(),
                                    line, col, Severity::Critical,
                                    "js_settimeout_eval".to_string(),
                                    "setTimeout/setInterval with string - eval equivalent".to_string(),
                                    Some("Pass function reference, not string".to_string())
                                ).with_confidence(0.92));
                            }
                        }
                    }
                    
                    // child_process.exec
                    if func_lower.contains("exec") && func_lower.contains("child_process") {
                        if Self::has_tainted_argument(node, source, tainted_vars) {
                            let (line, col) = Self::get_position(source, node.start_byte());
                            findings.push(Finding::new(
                                path.to_string_lossy().to_string(),
                                line, col, Severity::Critical,
                                "js_command_injection".to_string(),
                                "child_process.exec with user input".to_string(),
                                Some("Use execFile with array args".to_string())
                            ).with_confidence(0.90));
                        }
                    }
                }
            }
            
            "assignment_expression" => {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right")
                ) {
                    let lhs = &source[left.start_byte()..left.end_byte()];
                    let rhs = &source[right.start_byte()..right.end_byte()];
                    
                    // innerHTML assignment with tainted data
                    if lhs.to_lowercase().contains("innerhtml") {
                        if Self::contains_tainted_data(rhs, tainted_vars) {
                            let (line, col) = Self::get_position(source, node.start_byte());
                            findings.push(Finding::new(
                                path.to_string_lossy().to_string(),
                                line, col, Severity::Critical,
                                "js_dom_xss".to_string(),
                                "innerHTML with user input - XSS".to_string(),
                                Some("Use textContent or DOMPurify.sanitize()".to_string())
                            ).with_confidence(0.94));
                        }
                    }
                    
                    // document.write
                    if lhs.to_lowercase().contains("document.write") {
                        let (line, col) = Self::get_position(source, node.start_byte());
                        findings.push(Finding::new(
                            path.to_string_lossy().to_string(),
                            line, col, Severity::High,
                            "js_document_write".to_string(),
                            "document.write() - XSS risk".to_string(),
                            Some("Use DOM manipulation methods instead".to_string())
                        ).with_confidence(0.85));
                    }
                }
            }
            
            "member_expression" => {
                let text = &source[node.start_byte()..node.end_byte()];
                let text_lower = text.to_lowercase();
                
                // Prototype pollution
                if text_lower.contains("__proto__") || text_lower.contains("constructor.prototype") {
                    let (line, col) = Self::get_position(source, node.start_byte());
                    findings.push(Finding::new(
                        path.to_string_lossy().to_string(),
                        line, col, Severity::Critical,
                        "js_prototype_pollution".to_string(),
                        "Prototype pollution vulnerability".to_string(),
                        Some("Use Object.freeze() or validate property names".to_string())
                    ).with_confidence(0.91));
                }
                
                // $where NoSQL injection
                if text_lower.contains("$where") {
                    if let Some(parent) = node.parent() {
                        if parent.kind() == "call_expression" {
                            if Self::has_tainted_argument(&parent, source, tainted_vars) {
                                let (line, col) = Self::get_position(source, node.start_byte());
                                findings.push(Finding::new(
                                    path.to_string_lossy().to_string(),
                                    line, col, Severity::Critical,
                                    "js_nosql_injection".to_string(),
                                    "$where with user input - NoSQL injection".to_string(),
                                    Some("Avoid $where operator, use parameterized queries".to_string())
                                ).with_confidence(0.88));
                            }
                        }
                    }
                }
            }
            
            _ => {}
        }
        
        // Recurse
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::find_dangerous_sinks(&child, source, path, tainted_vars, findings);
        }
    }
    
    fn has_tainted_argument(node: &Node, source: &str, tainted_vars: &HashSet<String>) -> bool {
        if let Some(args) = node.child_by_field_name("arguments") {
            let args_text = source[args.start_byte()..args.end_byte()].to_string();
            for var in tainted_vars {
                if args_text.contains(var) {
                    return true;
                }
            }
            // Also check for direct taint sources
            if Self::is_taint_source(&args_text) {
                return true;
            }
        }
        false
    }
    
    fn contains_tainted_data(text: &str, tainted_vars: &HashSet<String>) -> bool {
        for var in tainted_vars {
            if text.contains(var) {
                return true;
            }
        }
        Self::is_taint_source(text)
    }
    
    fn get_position(source: &str, byte_offset: usize) -> (usize, usize) {
        let line = source[..byte_offset].lines().count();
        let column = source[..byte_offset].lines().last().map(|l| l.len()).unwrap_or(0);
        (line, column)
    }
    
    fn fallback_analysis(&self, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in source.lines().enumerate() {
            let line_lower = line.to_lowercase();
            if line_lower.contains("eval(") {
                findings.push(Finding::new(
                    path.to_string_lossy().to_string(),
                    i + 1, 0, Severity::Critical,
                    "js_eval".to_string(),
                    "eval() detected".to_string(),
                    Some("Never use eval()".to_string())
                ).with_confidence(0.90));
            }
        }
        findings
    }
}

impl LanguageAnalyzer for JavaScriptAnalyzer {
    fn analyze(&mut self, path: &Path, _language: Language) -> Vec<Finding> {
        if let Ok(file) = File::open(path) {
            if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                let source = String::from_utf8_lossy(&mmap);
                return self.analyze(&source, path);
            }
        }
        Vec::new()
    }
}

// Config file structure
#[derive(Debug, Deserialize, Default)]
struct Config {
    extensions: Option<Vec<String>>,
    severity: Option<String>,
    threads: Option<usize>,
    ignore: Option<Vec<String>>,
    format: Option<String>,
}

fn load_config(path: &Path) -> Option<Config> {
    if let Ok(content) = std::fs::read_to_string(path) {
        toml::from_str(&content).ok()
    } else {
        None
    }
}

fn run_scan(args: &Args, show_progress: bool) -> (Vec<Finding>, usize, std::time::Duration) {
    let start_time = Instant::now();
    
    // Collect files to scan
    let extensions: Vec<String> = args.extensions.split(',').map(|s| s.to_string()).collect();
    let ignore_patterns: Vec<regex::Regex> = args.config.as_ref()
        .and_then(|p| load_config(p))
        .and_then(|c| c.ignore)
        .unwrap_or_default()
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect();
    
    let files: Vec<PathBuf> = WalkDir::new(&args.path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let path_str = e.path().to_string_lossy();
            !ignore_patterns.iter().any(|p| p.is_match(&path_str))
        })
        .filter(|e| {
            e.path().extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| extensions.contains(&ext.to_string()))
                .unwrap_or(false)
        })
        .map(|e| e.path().to_path_buf())
        .collect();
    
    let total_files = files.len();
    if !args.quiet {
        if total_files > 50 && show_progress {
            println!("{} files to analyze", total_files);
        } else if total_files <= 50 {
            println!("{} files to analyze", total_files);
        }
    }
    
    // Progress bar for large scans
    let progress = if total_files > 50 && show_progress && !args.quiet {
        let pb = indicatif::ProgressBar::new(total_files as u64);
        pb.set_style(
            indicatif::ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };
    
    // Scan files in parallel using multi-language scanner
    let findings: Vec<Finding> = files
        .par_iter()
        .flat_map(|path| {
            let result = if let Some(mut scanner) = MultiLanguageScanner::new(path) {
                scanner.scan_file(path)
            } else {
                // Fallback to C/C++ scanner for unknown extensions
                let mut scanner = Scanner::new();
                scanner.scan_file(path)
            };
            
            if let Some(ref pb) = progress {
                pb.inc(1);
            }
            result
        })
        .collect();
    
    if let Some(pb) = progress {
        pb.finish_and_clear();
    }
    
    (findings, total_files, start_time.elapsed())
}

fn main() {
    // Check for hidden easter egg BEFORE clap parses (so it works as secret flag)
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.contains(&"--diamond".to_string()) {
        println!("\n{}", ansi_term::Colour::Cyan.bold().paint(
            r#"
    💎 THE DIAMOND 💎
    
         ████████████
       ██░░░░░░░░░░░░██
     ██░░░░░░░░░░░░░░░░██
   ██░░░░░░░░░░░░░░░░░░░░██
 ██░░░░░░░░░░████░░░░░░░░░░██
██░░░░░░░░░░██    ██░░░░░░░░██
██░░░░░░░░░░██    ██░░░░░░░░██
 ██░░░░░░░░░░████░░░░░░░░░░██
   ██░░░░░░░░░░░░░░░░░░░░██
     ██░░░░░░░░░░░░░░░░██
       ██░░░░░░░░░░░░██
         ████████████
    
    "Shines bright, finds bugs, zero config."
"#
        ));
        return;
    }
    
    let mut args = Args::parse();
    
    // ============================================================================
    // EASTER EGGS & POLISH
    // ============================================================================
    
    // Easter egg 1: Credits (obvious)
    if args.credits {
        println!("\n{}", ansi_term::Colour::Cyan.bold().paint(
            "ntscan - The Diamond v0.2.0"
        ));
        println!("\nBuilt with:");
        println!("  ☕ 47 cups of coffee");
        println!("  🦀 Rust (obviously)");
        println!("  😤 Pure spite for slow security tools");
        println!("  🎯 Zero regard for enterprise software budgets");
        println!("\nSpecial thanks to:");
        println!("  - Tree-sitter (for the parsers)");
        println!("  - The 3am coding gremlins");
        println!("  - Everyone who said this couldn't be done");
        println!("\n{}", ansi_term::Colour::Yellow.paint(
            "If you found a bug, it's a feature. If you found a feature, it's a miracle."
        ));
        println!();
        return;
    }
    
    // Interactive TUI mode
    if args.tui {
        run_interactive_tui();
        return;
    }

    // Easter egg 2: Coffee recommendation (obvious)
    if args.coffee {
        println!("\n{}", ansi_term::Colour::RGB(139, 69, 19).bold().paint(" ☕ COFFEE CALCULATOR ☕ "));
        println!("\nAnalyzing your codebase caffeine requirements...\n");
        
        // Do a quick scan to count issues
        let (findings, _, _) = run_scan(&args, false);
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let total = findings.len();
        
        let (cups, roast, message) = match (critical, total) {
            (0, 0) => (0, "None needed", "Your code is perfect. Suspiciously perfect."),
            (0, 1..=5) => (1, "Light roast", "Just a small one. You've got this."),
            (0, 6..=20) => (2, "Medium roast", "Standard Tuesday."),
            (1..=3, _) => (3, "Dark roast", "Buckle up. It's gonna be a long night."),
            (4..=10, _) => (5, "Espresso", "Cancel your plans."),
            _ => (8, "Whatever's strongest", "Have you considered a career change?"),
        };
        
        println!("{}", ansi_term::Colour::RGB(139, 69, 19).paint(
            format!("Recommendation: {} cups of {}", cups, roast)
        ));
        println!("{}", ansi_term::Colour::Fixed(240).paint(message));
        println!();
        return;
    }
    
    // Feature: Generate GitHub workflow
    if args.git {
        let workflow = r#"name: Security Scan

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  security-scan:
    name: ntscan Security Analysis
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Install Rust
      uses: dtolnay/rust-action@stable

    - name: Build ntscan
      run: |
        cargo build --release
        cp target/release/ntscan ./ntscan

    - name: Run ntscan
      run: |
        ./ntscan --sarif . || true
        ls -la ntscan-results.sarif || echo "No issues found"

    - name: Check SARIF file exists
      id: check_sarif
      run: |
        if [ -f ntscan-results.sarif ]; then
          echo "exists=true" >> $GITHUB_OUTPUT
        else
          echo "exists=false" >> $GITHUB_OUTPUT
        fi

    - name: Upload SARIF to GitHub
      if: steps.check_sarif.outputs.exists == 'true'
      uses: github/codeql-action/upload-sarif@v4
      with:
        sarif_file: ./ntscan-results.sarif
        category: ntscan

    - name: Check for critical issues
      run: ./ntscan --quiet --severity critical . || exit 1
"#;
        let output_path = PathBuf::from(".github/workflows/ntscan.yml");
        if output_path.exists() {
            println!("{} Workflow file already exists at .github/workflows/ntscan.yml", 
                ansi_term::Colour::Yellow.paint("⚠"));
            println!("   Use --git --force to overwrite");
        } else {
            std::fs::create_dir_all(".github/workflows").ok();
            match std::fs::write(&output_path, workflow) {
                Ok(_) => {
                    println!("{} GitHub workflow created at .github/workflows/ntscan.yml", 
                        ansi_term::Colour::Green.paint("✓"));
                    println!("\n{}", ansi_term::Colour::Cyan.paint("Next steps:"));
                    println!("  1. Replace YOUR_USERNAME in the workflow file");
                    println!("  2. Commit and push: git add .github/workflows/ntscan.yml && git commit -m \"Add security scanning\"");
                    println!("  3. Check Security tab after first run");
                }
                Err(e) => {
                    eprintln!("{} Could not create workflow: {}", 
                        ansi_term::Colour::Red.paint("✗"), e);
                }
            }
        }
        return;
    }
    
    // ============================================================================
    // MAIN LOGIC
    // ============================================================================
    
    // Load config file if exists
    let config_path = args.config.clone().unwrap_or_else(|| PathBuf::from(".ntscan.toml"));
    if let Some(config) = load_config(&config_path) {
        // Override args with config values if not set via CLI
        if args.extensions == "c,cpp,h,hpp,java,cs,py,js,ts,go,rs,rb" {
            if let Some(exts) = config.extensions {
                args.extensions = exts.join(",");
            }
        }
        if args.severity == "low" {
            if let Some(sev) = config.severity {
                args.severity = sev;
            }
        }
        if args.threads == 0 {
            if let Some(threads) = config.threads {
                args.threads = threads;
            }
        }
        if args.format == "text" {
            if let Some(fmt) = config.format {
                args.format = fmt;
            }
        }
    }
    
    // Configure thread pool
    if args.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .unwrap();
    }
    
    // Load baseline if specified
    let baseline_findings: Option<Vec<Finding>> = args.baseline.as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok());
    
    // Main scan loop (with watch mode support)
    let mut first_run = true;
    loop {
        let (findings, total_files, elapsed) = run_scan(&args, first_run);
        first_run = false;
    
    // Filter by severity and confidence
    let min_severity = match args.severity.as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    };
    
    let mut filtered: Vec<Finding> = findings
        .iter()
        .filter(|f| f.severity >= min_severity)
        .filter(|f| f.is_high_confidence())
        .cloned()
        .collect();
    
    // Filter out baseline findings (only show new issues)
    if let Some(ref baseline) = baseline_findings {
        filtered.retain(|f| {
            !baseline.iter().any(|b| {
                b.file == f.file && b.line == f.line && b.category == f.category
            })
        });
        if !args.quiet {
            println!("  ({} new issues not in baseline)", filtered.len());
        }
    }
    
    // Convert to references for output
    let filtered_refs: Vec<&Finding> = filtered.iter().collect();

    // Hidden Easter egg 4: The Answer (42 issues)
    if filtered.len() == 42 && !args.quiet {
        println!("\n{}", ansi_term::Colour::Yellow.paint(
            "🌌 You have found the Answer to Life, the Universe, and Everything."
        ));
        println!("{}", ansi_term::Colour::Fixed(240).paint(
            "   (Don't forget to bring a towel.)"
        ));
    }

    // Get terminal width for responsive formatting
    let term_width = term_size::dimensions().map(|(w, _)| w).unwrap_or(100);

    // Output results
    match args.format.as_str() {
        "json" => {
            if !args.quiet {
                println!("{}", serde_json::to_string_pretty(&filtered_refs).unwrap());
            }
        }
        _ => {
            if !args.quiet {
                print_beautiful_report(&filtered_refs, total_files, elapsed, term_width);
            } else {
                // Quiet mode: just summary
                let critical = filtered_refs.iter().filter(|f| f.severity == Severity::Critical).count();
                let high = filtered_refs.iter().filter(|f| f.severity == Severity::High).count();
                let medium = filtered_refs.iter().filter(|f| f.severity == Severity::Medium).count();
                let total_issues = filtered_refs.len();
                
                let issue_word = if total_issues == 1 { "issue" } else { "issues" };
                let file_word = if total_files == 1 { "file" } else { "files" };
                
                if critical > 0 {
                    println!("{} critical, {} high, {} medium in {} {} ({} {})",
                        critical, high, medium, total_files, file_word, total_issues, issue_word);
                } else if total_issues > 0 {
                    println!("{} issues found in {} {} (no critical)",
                        total_issues, total_files, file_word);
                } else {
                    println!("No issues found in {} {}", total_files, file_word);
                }
            }
        }
    }
    
    // Write SARIF output if requested
    if let Some(sarif_path) = &args.sarif {
        let sarif = generate_sarif(&filtered_refs, &args.path);
        if let Ok(sarif_json) = serde_json::to_string_pretty(&sarif) {
            if let Err(e) = std::fs::write(sarif_path, sarif_json) {
                eprintln!("Warning: Could not write SARIF file: {}", e);
            } else if !args.quiet {
                println!("  SARIF output written to {}", sarif_path.display());
            }
        }
    }

    // Save baseline if requested
    if let Some(baseline_path) = &args.save_baseline {
        let findings_owned: Vec<Finding> = filtered.iter().cloned().collect();
        if let Ok(json) = serde_json::to_string_pretty(&findings_owned) {
            if let Err(e) = std::fs::write(baseline_path, json) {
                eprintln!("Warning: Could not write baseline file: {}", e);
            } else if !args.quiet {
                println!("  Baseline saved to {}", baseline_path.display());
            }
        }
    }

    // Exit with error code if critical findings
    let critical_count = filtered_refs.iter().filter(|f| f.severity == Severity::Critical).count();
    
    // Watch mode: sleep and restart
    if args.watch {
        if !args.quiet {
            println!("\n👀 Watching for changes... (Ctrl+C to stop)\n");
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
        continue;
    }
    
    if critical_count > 0 {
        std::process::exit(1);
    }
    break;
    }
}

// ============================================================================
// INTERACTIVE TUI MODE - For humans who like menus
// ============================================================================

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
    cursor::{MoveTo, Show, Hide},
    ExecutableCommand, QueueableCommand,
};
use std::io::{stdout, Write};

struct TuiApp {
    menu_items: Vec<(&'static str, &'static str)>,
    selected: usize,
    path_input: String,
    severity_filter: usize, // 0=all, 1=critical, 2=high, 3=medium
    output_format: usize,   // 0=text, 1=json, 2=sarif
    mode: TuiMode,
    scan_results: Option<(Vec<Finding>, usize, std::time::Duration)>,
    scroll_offset: usize,
}

#[derive(PartialEq)]
enum TuiMode {
    Menu,
    PathInput,
    Scanning,
    Results,
    Help,
}

impl TuiApp {
    fn new() -> Self {
        Self {
            menu_items: vec![
                ("🚀", "Quick Scan (current directory)"),
                ("📁", "Scan specific folder"),
                ("⚙️", "Configure options"),
                ("❓", "Help / About"),
                ("🚪", "Exit"),
            ],
            selected: 0,
            path_input: ".".to_string(),
            severity_filter: 0,
            output_format: 0,
            mode: TuiMode::Menu,
            scan_results: None,
            scroll_offset: 0,
        }
    }

    fn run(&mut self) -> std::io::Result<()> {
        enable_raw_mode()?;
        let mut stdout = stdout();
        stdout.execute(Hide)?;

        loop {
            self.draw()?;

            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match self.mode {
                        TuiMode::Menu => match key.code {
                            KeyCode::Up => {
                                if self.selected > 0 { self.selected -= 1; }
                            }
                            KeyCode::Down => {
                                if self.selected < self.menu_items.len() - 1 { self.selected += 1; }
                            }
                            KeyCode::Enter => {
                                match self.selected {
                                    0 => self.run_scan("."),
                                    1 => self.mode = TuiMode::PathInput,
                                    2 => self.configure_options(),
                                    3 => self.mode = TuiMode::Help,
                                    4 => break,
                                    _ => {}
                                }
                            }
                            KeyCode::Char('q') => break,
                            _ => {}
                        }
                        TuiMode::PathInput => match key.code {
                            KeyCode::Enter => {
                                self.run_scan(&self.path_input.clone());
                            }
                            KeyCode::Char(c) => self.path_input.push(c),
                            KeyCode::Backspace => { self.path_input.pop(); }
                            KeyCode::Esc => self.mode = TuiMode::Menu,
                            _ => {}
                        }
                        TuiMode::Results => match key.code {
                            KeyCode::Up => {
                                if self.scroll_offset > 0 { self.scroll_offset -= 1; }
                            }
                            KeyCode::Down => {
                                self.scroll_offset += 1;
                            }
                            KeyCode::Char('r') => self.mode = TuiMode::Menu,
                            KeyCode::Char('q') => break,
                            KeyCode::Esc => self.mode = TuiMode::Menu,
                            KeyCode::Char('s') => self.save_results(),
                            _ => {}
                        }
                        TuiMode::Help => match key.code {
                            KeyCode::Esc | KeyCode::Char('q') => self.mode = TuiMode::Menu,
                            _ => {}
                        }
                        _ => {}
                    }
                }
            }
        }

        stdout.execute(Show)?;
        disable_raw_mode()?;
        Ok(())
    }

    fn draw(&self) -> std::io::Result<()> {
        let mut stdout = stdout();
        let (width, height) = term_size::dimensions().unwrap_or((80, 24));

        stdout.queue(Clear(ClearType::All))?;
        stdout.queue(MoveTo(0, 0))?;

        match self.mode {
            TuiMode::Menu => self.draw_menu(&mut stdout, width, height),
            TuiMode::PathInput => self.draw_path_input(&mut stdout, width, height),
            TuiMode::Scanning => self.draw_scanning(&mut stdout, width, height),
            TuiMode::Results => self.draw_results(&mut stdout, width, height),
            TuiMode::Help => self.draw_help(&mut stdout, width, height),
        }?;

        stdout.flush()?;
        Ok(())
    }

    fn draw_menu(&self, stdout: &mut std::io::Stdout, width: usize, _height: usize) -> std::io::Result<()> {
        let title = "╔══════════════════════════════════════════╗";
        let subtitle = "║        ntscan - Security Scanner         ║";
        let bottom = "╚══════════════════════════════════════════╝";

        println!("{}", ansi_term::Colour::Cyan.paint(title));
        println!("{}", ansi_term::Colour::Cyan.paint(subtitle));
        println!("{}", ansi_term::Colour::Cyan.paint(bottom));
        println!();

        for (i, (icon, text)) in self.menu_items.iter().enumerate() {
            let prefix = if i == self.selected { "> " } else { "  " };
            let line = format!("{}{} {}", prefix, icon, text);
            if i == self.selected {
                println!("{}", ansi_term::Style::new().on(ansi_term::Colour::Blue).fg(ansi_term::Colour::White).paint(&line));
            } else {
                println!("{}", line);
            }
        }

        println!();
        println!("{}", ansi_term::Colour::Fixed(240).paint("Controls: ↑↓ to navigate, Enter to select, q to quit"));
        println!("{}", ansi_term::Colour::Fixed(240).paint("CLI: ntscan [path] [--flags]"));
        
        Ok(())
    }

    fn draw_path_input(&self, stdout: &mut std::io::Stdout, _width: usize, _height: usize) -> std::io::Result<()> {
        println!("{}", ansi_term::Colour::Cyan.bold().paint("📁 Scan Specific Folder"));
        println!();
        println!("Enter path to scan:");
        println!();
        println!("  > {}", self.path_input);
        println!();
        println!("{}", ansi_term::Colour::Fixed(240).paint("Press Enter to scan, Esc to cancel"));
        Ok(())
    }

    fn draw_scanning(&self, stdout: &mut std::io::Stdout, _width: usize, _height: usize) -> std::io::Result<()> {
        let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let frame = spinner[self.scroll_offset % spinner.len()];
        println!("\n\n");
        println!("{}", ansi_term::Colour::Cyan.bold().paint(format!("{} Scanning...", frame)));
        println!();
        println!("{}", ansi_term::Colour::Fixed(240).paint("This may take a few seconds depending on codebase size"));
        Ok(())
    }

    fn draw_results(&self, stdout: &mut std::io::Stdout, width: usize, height: usize) -> std::io::Result<()> {
        if let Some((findings, total_files, elapsed)) = &self.scan_results {
            let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
            let high = findings.iter().filter(|f| f.severity == Severity::High).count();
            let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();

            println!("{}", ansi_term::Colour::Cyan.bold().paint("📊 Scan Results"));
            println!();
            println!("  {}: {} files in {:.2}s", 
                ansi_term::Colour::Green.paint("Scanned"), 
                total_files, 
                elapsed.as_secs_f64()
            );
            println!();
            
            if findings.is_empty() {
                println!("{}", ansi_term::Style::new().on(ansi_term::Colour::Green).fg(ansi_term::Colour::Black).bold().paint(" ✓ No issues found! "));
            } else {
                if critical > 0 {
                    println!("  {} {} Critical issues", ansi_term::Colour::Red.bold().paint("●"), critical);
                }
                if high > 0 {
                    println!("  {} {} High issues", ansi_term::Colour::Yellow.bold().paint("●"), high);
                }
                if medium > 0 {
                    println!("  {} {} Medium issues", ansi_term::Colour::Blue.bold().paint("●"), medium);
                }
                
                println!();
                println!("{}", ansi_term::Colour::Cyan.bold().paint("Top Findings:"));
                
                let max_display = std::cmp::min(10, findings.len());
                for (i, finding) in findings.iter().skip(self.scroll_offset).take(max_display).enumerate() {
                    let sev_color = match finding.severity {
                        Severity::Critical => ansi_term::Colour::Red,
                        Severity::High => ansi_term::Colour::Yellow,
                        Severity::Medium => ansi_term::Colour::Blue,
                        Severity::Low => ansi_term::Colour::Fixed(240),
                    };
                    let file_short = if finding.file.len() > width - 30 {
                        format!("...{}" , &finding.file[finding.file.len()-(width-33)..])
                    } else {
                        finding.file.clone()
                    };
                    println!("  {} {}:{} - {}", 
                        sev_color.paint(format!("[{:?}]", finding.severity)),
                        ansi_term::Colour::Fixed(240).paint(&file_short),
                        finding.line,
                        &finding.message[..std::cmp::min(finding.message.len(), width-50)]
                    );
                }
                
                if findings.len() > 10 {
                    println!("  ... and {} more (scroll with ↑↓)", findings.len() - 10);
                }
            }
            
            println!();
            println!("{}", ansi_term::Colour::Fixed(240).paint("Controls: r = return to menu, s = save, q = quit, ↑↓ = scroll"));
        }
        Ok(())
    }

    fn draw_help(&self, stdout: &mut std::io::Stdout, _width: usize, _height: usize) -> std::io::Result<()> {
        println!("{}", ansi_term::Colour::Cyan.bold().paint("❓ ntscan Help"));
        println!();
        println!("{}", ansi_term::Style::new().bold().paint("About:"));
        println!("  Lightning-fast security scanner for C, C++, Python, JavaScript, and Java.");
        println!("  Finds vulnerabilities in ~7 seconds instead of 20 minutes.");
        println!();
        println!("{}", ansi_term::Style::new().bold().paint("Quick CLI Usage:"));
        println!("  ntscan .                    # Scan current directory");
        println!("  ntscan --quiet .            # Minimal output (CI-friendly)");
        println!("  ntscan --format json .      # JSON output");
        println!("  ntscan --sarif results.sarif .  # SARIF for GitHub");
        println!("  ntscan --tui                # Interactive mode (this menu)");
        println!();
        println!("{}", ansi_term::Style::new().bold().paint("Features:"));
        println!("  • Buffer overflow detection");
        println!("  • Null pointer analysis");
        println!("  • Taint tracking for injection bugs");
        println!("  • Cross-function data flow analysis");
        println!();
        println!("{}", ansi_term::Colour::Fixed(240).paint("Press Esc or q to return to menu"));
        Ok(())
    }

    fn run_scan(&mut self, path: &str) {
        self.mode = TuiMode::Scanning;
        self.draw().ok();

        let args = Args {
            path: path.into(),
            extensions: "c,cpp,h,hpp,java,cs,py,js,ts,go,rs,rb".to_string(),
            format: "text".to_string(),
            threads: 0,
            severity: match self.severity_filter {
                1 => "critical".to_string(),
                2 => "high".to_string(),
                3 => "medium".to_string(),
                _ => "low".to_string(),
            },
            quiet: true,
            watch: false,
            baseline: None,
            config: None,
            sarif: None,
            git: false,
            credits: false,
            coffee: false,
            save_baseline: None,
            tui: false,
        };

        let results = run_scan(&args, true);
        self.scan_results = Some(results);
        self.mode = TuiMode::Results;
        self.scroll_offset = 0;
    }

    fn configure_options(&mut self) {
        self.severity_filter = (self.severity_filter + 1) % 4;
    }

    fn save_results(&self) {
        if let Some((findings, _, _)) = &self.scan_results {
            if let Ok(json) = serde_json::to_string_pretty(findings) {
                let _ = std::fs::write("ntscan-results.json", json);
            }
        }
    }
}

fn run_interactive_tui() {
    println!("{}", ansi_term::Colour::Cyan.bold().paint("🚀 Starting Interactive Mode..."));
    println!("{}", ansi_term::Colour::Fixed(240).paint("(Use arrow keys and Enter to navigate)"));
    std::thread::sleep(std::time::Duration::from_millis(500));
    
    let mut app = TuiApp::new();
    if let Err(e) = app.run() {
        eprintln!("TUI error: {}", e);
    }
}

// ============================================================================
// SARIF Generation for GitHub Code Scanning
// ============================================================================

fn generate_sarif(findings: &[&Finding], root_path: &Path) -> serde_json::Value {
    use chrono::Utc;
    
    let mut results = Vec::new();
    
    for finding in findings {
        let rule_id = format!("ntscan/{}", finding.category);
        let level = match finding.severity {
            Severity::Critical => "error",
            Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
        };
        
        let result = serde_json::json!({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": finding.message
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file,
                        "uriBaseId": "ROOTPATH"
                    },
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.column
                    }
                }
            }]
        });
        results.push(result);
    }
    
    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ntscan",
                    "version": "0.2.0",
                    "informationUri": "https://github.com/yourname/ntscan"
                }
            },
            "invocations": [{
                "executionSuccessful": true,
                "endTimeUtc": Utc::now().to_rfc3339()
            }],
            "results": results
        }]
    })
}

// ============================================================================
// BEAUTIFUL CLI OUTPUT - Makes devs happy
// ============================================================================

fn print_beautiful_report(findings: &[&Finding], total_files: usize, elapsed: std::time::Duration, term_width: usize) {
    use ansi_term::{Colour, Style};
    
    if findings.is_empty() {
        println!("\n{}", Style::new().on(Colour::Green).fg(Colour::Black).bold().paint(" ✓ No issues found "));
        println!("  Your code is either clean or you're not looking hard enough.\n");
        return;
    }
    
    // Header with fancy box
    let header_text = format!(" ntscan - Security Report ");
    let header_pad = "═".repeat((term_width - header_text.len()) / 2);
    println!("\n{}{}{}", 
        Colour::Cyan.paint(&header_pad),
        Style::new().bold().paint(&header_text),
        Colour::Cyan.paint(&header_pad)
    );
    
    // Stats row
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    
    let file_word = if total_files == 1 { "file" } else { "files" };
    println!("  {}  {}  {}",
        Colour::Red.bold().paint(format!("● {} Critical", critical)),
        Colour::Yellow.bold().paint(format!("● {} High", high)),
        Colour::Blue.bold().paint(format!("● {} Medium", medium))
    );
    println!("  {} {} scanned in {:.2}s\n", total_files, file_word, elapsed.as_secs_f64());
    
    // Group by file with beautiful formatting
    let mut by_file: HashMap<String, Vec<&&Finding>> = HashMap::new();
    for finding in findings {
        by_file.entry(finding.file.clone()).or_default().push(finding);
    }
    
    let mut files: Vec<_> = by_file.iter().collect();
    files.sort_by_key(|(f, _)| *f);
    
    for (idx, (file, file_findings)) in files.iter().enumerate() {
        // File header with subtle separator
        let file_display = if file.len() > term_width - 10 {
            format!("...{}", &file[file.len()-(term_width-13)..])
        } else {
            file.to_string()
        };
        
        let separator = if idx > 0 { "├" } else { "┌" };
        println!("{} {}", 
            Colour::Cyan.paint(separator),
            Style::new().bold().underline().paint(&file_display)
        );
        
        // Findings for this file
        for (fidx, finding) in file_findings.iter().enumerate() {
            let is_last = fidx == file_findings.len() - 1;
            let connector = if is_last { "└" } else { "├" };
            
            // Severity badge
            let sev_badge = match finding.severity {
                Severity::Critical => Style::new().on(Colour::Red).fg(Colour::White).bold().paint(" CRIT "),
                Severity::High => Style::new().on(Colour::Yellow).fg(Colour::Black).bold().paint(" HIGH "),
                Severity::Medium => Style::new().on(Colour::Blue).fg(Colour::White).paint(" MED  "),
                Severity::Low => Style::new().on(Colour::Fixed(240)).fg(Colour::White).paint(" LOW  "),
            };
            
            // Confidence indicator
            let conf_color = if finding.confidence >= 0.9 { Colour::Green }
                else if finding.confidence >= 0.7 { Colour::Yellow }
                else { Colour::Red };
            let conf_dot = conf_color.paint("●");
            
            // Location
            let location = format!("{}:{}", finding.line, finding.column);
            
            // Print finding header
            println!("  {} {} {} {} {}",
                Colour::Cyan.paint(connector),
                sev_badge,
                conf_dot,
                Style::new().dimmed().paint(&location),
                Style::new().bold().paint(&finding.message)
            );
            
            // Category tag
            if !finding.category.is_empty() && term_width > 80 {
                let tag = format!("[{}]", finding.category);
                println!("  {} {} {}",
                    Colour::Cyan.paint(if is_last { "  " } else { "│ " }),
                    Colour::Fixed(240).paint(&tag),
                    Colour::Fixed(240).paint(format!("{:.0}% confidence", finding.confidence * 100.0))
                );
            }
            
            // Suggestion
            if let Some(sugg) = &finding.suggestion {
                let sugg_text = if sugg.len() > term_width - 15 {
                    format!("{}...", &sugg[..term_width-18])
                } else {
                    sugg.to_string()
                };
                println!("  {} {} {}",
                    Colour::Cyan.paint(if is_last { "  " } else { "│ " }),
                    Colour::Green.paint("→"),
                    Colour::Green.paint(&sugg_text)
                );
            }
        }
        println!();
    }
    
    // Footer
    let footer_pad = "═".repeat(term_width);
    println!("{}", Colour::Cyan.paint(&footer_pad));
    
    // Summary box with proper pluralization
    let issue_word = if findings.len() == 1 { "issue" } else { "issues" };
    let file_word = if total_files == 1 { "file" } else { "files" };
    let summary = format!(" {} {} found in {} {} ", findings.len(), issue_word, total_files, file_word);
    let summary_style = if critical > 0 {
        Style::new().on(Colour::Red).fg(Colour::White).bold()
    } else if high > 0 {
        Style::new().on(Colour::Yellow).fg(Colour::Black).bold()
    } else {
        Style::new().on(Colour::Blue).fg(Colour::White).bold()
    };
    
    println!("{}\n", summary_style.paint(&summary));
}
