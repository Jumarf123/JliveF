use colored::*;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Violation,
    Warning,
    Ok,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: String,
    pub path: String,
    pub key: String,
    pub value: Option<String>,
    pub message: String,
}

impl Finding {
    pub fn new(
        rule: impl Into<String>,
        path: impl Into<String>,
        key: impl Into<String>,
        value: Option<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule: rule.into(),
            path: path.into(),
            key: key.into(),
            value,
            message: message.into(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub violations: Vec<Finding>,
    pub warnings: Vec<Finding>,
    pub checked_items: u32,
}

impl Report {
    pub fn new() -> Self {
        Self {
            violations: Vec::new(),
            warnings: Vec::new(),
            checked_items: 0,
        }
    }

    pub fn add_violation(&mut self, finding: Finding) {
        self.violations.push(finding);
    }

    pub fn add_warning(&mut self, finding: Finding) {
        self.warnings.push(finding);
    }

    pub fn inc_checked(&mut self) {
        self.checked_items = self.checked_items.saturating_add(1);
    }

    pub fn print(&self) {
        println!("==============================");
        println!("Результаты сканирования");
        println!("Проверено пунктов: {}", self.checked_items);
        println!("==============================");

        if self.violations.is_empty() {
            println!("{}", "Всё в норме. Нарушений не найдено.".green());
        } else {
            println!("Выявленные нарушения:");
            for v in &self.violations {
                println!("{} [{}] {}", "?".red(), v.rule, v.message);
                println!("   Путь: {}", v.path);
                println!("   Ключ: {}", v.key);
                if let Some(val) = &v.value {
                    println!("   Значение: {}", val);
                }
            }
        }

        if !self.warnings.is_empty() {
            println!();
            println!("Предупреждения:");
            for w in &self.warnings {
                println!("{} [{}] {}", "?".yellow(), w.rule, w.message);
                println!("   Путь: {}", w.path);
                if !w.key.is_empty() {
                    println!("   Ключ: {}", w.key);
                }
                if let Some(val) = &w.value {
                    println!("   Значение: {}", val);
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn build_report_for_tests() -> Report {
    Report::new()
}
