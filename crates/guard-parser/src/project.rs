//! Loading and parsing a set of source files into a [`Project`].

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use syn::visit_mut::VisitMut;

use crate::cargo::{CrateInfo, CrateResolver};
use crate::discover::{discover, DiscoverError, DiscoverOptions};
use crate::syntax::{attr_is, is_test_attr};

/// A parsed source file.
#[derive(Debug)]
pub struct SourceFile {
    /// Path on disk (as discovered).
    pub path: PathBuf,
    /// Path used in reports: relative to the current directory when possible,
    /// always with `/` separators.
    pub display_path: String,
    /// Raw file contents.
    pub text: String,
    /// Parsed syntax tree with test-only items removed (unless tests are included).
    pub ast: syn::File,
    /// Index into [`Project::crates`].
    pub crate_id: usize,
}

impl SourceFile {
    /// The text of 1-based line `line`, without the trailing newline.
    pub fn line(&self, line: usize) -> Option<&str> {
        self.text.lines().nth(line.checked_sub(1)?)
    }

    /// `true` if the file references the Soroban SDK.
    pub fn mentions_soroban(&self) -> bool {
        self.text.contains("soroban_sdk")
    }
}

/// A file that could not be read or parsed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParseFailure {
    pub file: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(transparent)]
    Discover(#[from] DiscoverError),
}

/// Every file of a scan plus per-crate metadata.
#[derive(Debug, Default)]
pub struct Project {
    pub files: Vec<SourceFile>,
    pub crates: Vec<CrateInfo>,
    pub failures: Vec<ParseFailure>,
}

impl Project {
    /// Discovers and parses all Rust files under `roots`.
    pub fn load(roots: &[PathBuf], opts: &DiscoverOptions) -> Result<Self, LoadError> {
        let mut paths = Vec::new();
        for root in roots {
            paths.extend(discover(root, opts)?);
        }
        paths.sort();
        paths.dedup();

        let cwd = std::env::current_dir().ok();
        let mut resolver = CrateResolver::new();
        let mut project = Project::default();
        // Files (and directories of submodules) belonging to `#[cfg(test)] mod x;`.
        let mut test_modules: HashSet<PathBuf> = HashSet::new();
        let mut test_dirs: Vec<PathBuf> = Vec::new();

        for path in paths {
            let display_path = display_path(&path, cwd.as_deref());
            let text = match fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => {
                    project.failures.push(ParseFailure {
                        file: display_path,
                        line: None,
                        column: None,
                        message: format!("failed to read file: {e}"),
                    });
                    continue;
                }
            };
            let crate_id = resolver.crate_for(&path);
            match parse_source(&text, opts.include_tests) {
                Ok((ast, test_mods)) => {
                    for m in test_mods {
                        let (files, dir) = module_file_candidates(&path, &m);
                        test_modules.extend(files);
                        test_dirs.extend(dir);
                    }
                    project.files.push(SourceFile { path, display_path, text, ast, crate_id });
                }
                Err(err) => project.failures.push(parse_failure(display_path, &err)),
            }
        }

        if !opts.include_tests && !test_modules.is_empty() {
            let canon = |p: &PathBuf| fs::canonicalize(p).unwrap_or_else(|_| p.clone());
            let files: HashSet<PathBuf> = test_modules.iter().map(canon).collect();
            let dirs: Vec<PathBuf> = test_dirs.iter().filter(|d| d.is_dir()).map(canon).collect();
            project.files.retain(|f| {
                let c = canon(&f.path);
                !files.contains(&c) && !dirs.iter().any(|d| c.starts_with(d))
            });
        }

        project.crates = resolver.into_crates();
        if !opts.include_tests {
            let crates = &project.crates;
            project.files.retain(|f| !crates.get(f.crate_id).is_some_and(|c| c.test_support));
        }
        Ok(project)
    }

    /// Builds a project from in-memory sources. Every file is placed in one
    /// synthetic crate described by `info`. Intended for tests and embedding.
    pub fn from_sources<'s>(
        sources: impl IntoIterator<Item = (&'s str, &'s str)>,
        info: CrateInfo,
        include_tests: bool,
    ) -> Self {
        let mut project = Project { crates: vec![info], ..Default::default() };
        for (name, text) in sources {
            match parse_source(text, include_tests) {
                Ok((ast, _)) => project.files.push(SourceFile {
                    path: PathBuf::from(name),
                    display_path: name.replace('\\', "/"),
                    text: text.to_string(),
                    ast,
                    crate_id: 0,
                }),
                Err(err) => project.failures.push(parse_failure(name.to_string(), &err)),
            }
        }
        project
    }

    /// Replaces a crate's discovered files with the crate-wide output of
    /// `cargo expand`. Findings use the primary source file's path; line numbers
    /// refer to expanded output.
    pub fn replace_crate_with_expanded_source(
        &mut self,
        crate_id: usize,
        text: &str,
        include_tests: bool,
    ) -> Result<(), ParseFailure> {
        let Some(first) = self.files.iter().find(|f| f.crate_id == crate_id) else {
            return Ok(());
        };
        let primary = ["src/lib.rs", "src/main.rs", "lib.rs", "main.rs"]
            .into_iter()
            .find(|path| self.files.iter().any(|f| f.crate_id == crate_id && f.path.ends_with(*path)));
        let original = primary
            .and_then(|path| self.files.iter().find(|f| f.crate_id == crate_id && f.path.ends_with(path)))
            .unwrap_or(first);
        let path = original.path.clone();
        let display_path = format!("{} (cargo expand)", original.display_path);
        let (ast, _) =
            parse_source(text, include_tests).map_err(|error| parse_failure(display_path.clone(), &error))?;
        self.files.retain(|f| f.crate_id != crate_id);
        self.files.push(SourceFile { path, display_path, text: text.to_string(), ast, crate_id });
        self.files.sort_by(|a, b| (&a.crate_id, &a.display_path).cmp(&(&b.crate_id, &b.display_path)));
        Ok(())
    }
}

fn parse_failure(file: String, err: &syn::Error) -> ParseFailure {
    let start = err.span().start();
    ParseFailure { file, line: Some(start.line), column: Some(start.column + 1), message: err.to_string() }
}

fn display_path(path: &Path, cwd: Option<&Path>) -> String {
    let rel = cwd
        .and_then(|cwd| {
            let abs = if path.is_absolute() { path.to_path_buf() } else { cwd.join(path) };
            abs.strip_prefix(cwd).ok().map(Path::to_path_buf)
        })
        .unwrap_or_else(|| path.to_path_buf());
    let s = rel.to_string_lossy().replace('\\', "/");
    s.strip_prefix("./").map(str::to_string).unwrap_or(s)
}

/// An out-of-line module declared under `#[cfg(test)]`.
struct TestModDecl {
    name: String,
    path_attr: Option<String>,
}

/// Parses `text`, removing test-only items unless `include_tests` is set.
/// Returns the tree and the out-of-line test modules it declares.
fn parse_source(text: &str, include_tests: bool) -> syn::Result<(syn::File, Vec<TestModDecl>)> {
    let mut ast = syn::parse_file(text)?;
    let mut mods = Vec::new();
    // A file starting with `#![cfg(test)]` is test code as a whole.
    if !include_tests && ast.attrs.iter().any(is_test_attr) {
        ast.items.clear();
        return Ok((ast, mods));
    }
    if !include_tests {
        let mut stripper = TestStripper { mods: &mut mods };
        stripper.visit_file_mut(&mut ast);
    }
    Ok((ast, mods))
}

struct TestStripper<'m> {
    mods: &'m mut Vec<TestModDecl>,
}

impl TestStripper<'_> {
    fn filter_items(&mut self, items: &mut Vec<syn::Item>, top_level: bool) {
        items.retain(|item| {
            let attrs = item_attrs(item);
            let is_test = attrs.iter().any(is_test_attr) || attrs.iter().any(|a| attr_is(a, "contracttest"));
            if is_test && top_level {
                if let syn::Item::Mod(m) = item {
                    if m.content.is_none() {
                        let path_attr =
                            m.attrs.iter().find(|a| a.path().is_ident("path")).and_then(|a| match &a.meta {
                                syn::Meta::NameValue(nv) => match &nv.value {
                                    syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.value()),
                                    _ => None,
                                },
                                _ => None,
                            });
                        self.mods.push(TestModDecl { name: m.ident.to_string(), path_attr });
                    }
                }
            }
            !is_test
        });
    }
}

impl VisitMut for TestStripper<'_> {
    fn visit_file_mut(&mut self, file: &mut syn::File) {
        self.filter_items(&mut file.items, true);
        syn::visit_mut::visit_file_mut(self, file);
    }

    fn visit_item_mod_mut(&mut self, m: &mut syn::ItemMod) {
        if let Some((_, items)) = &mut m.content {
            self.filter_items(items, false);
        }
        syn::visit_mut::visit_item_mod_mut(self, m);
    }

    fn visit_item_impl_mut(&mut self, imp: &mut syn::ItemImpl) {
        imp.items.retain(|it| match it {
            syn::ImplItem::Fn(f) => !f.attrs.iter().any(is_test_attr),
            _ => true,
        });
        syn::visit_mut::visit_item_impl_mut(self, imp);
    }

    fn visit_block_mut(&mut self, block: &mut syn::Block) {
        block.stmts.retain(|s| match s {
            syn::Stmt::Item(item) => !item_attrs(item).iter().any(is_test_attr),
            _ => true,
        });
        syn::visit_mut::visit_block_mut(self, block);
    }
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    use syn::Item::*;
    match item {
        Const(i) => &i.attrs,
        Enum(i) => &i.attrs,
        ExternCrate(i) => &i.attrs,
        Fn(i) => &i.attrs,
        ForeignMod(i) => &i.attrs,
        Impl(i) => &i.attrs,
        Macro(i) => &i.attrs,
        Mod(i) => &i.attrs,
        Static(i) => &i.attrs,
        Struct(i) => &i.attrs,
        Trait(i) => &i.attrs,
        TraitAlias(i) => &i.attrs,
        Type(i) => &i.attrs,
        Union(i) => &i.attrs,
        Use(i) => &i.attrs,
        _ => &[],
    }
}

/// Possible file locations of `mod name;` declared in `file`, plus the
/// directory holding its submodules.
fn module_file_candidates(file: &Path, m: &TestModDecl) -> (Vec<PathBuf>, Option<PathBuf>) {
    let Some(dir) = file.parent() else { return (vec![], None) };
    if let Some(p) = &m.path_attr {
        let target = dir.join(p);
        let is_mod_rs = target.file_name().is_some_and(|n| n == "mod.rs");
        let sub = target.parent().filter(|_| is_mod_rs).map(Path::to_path_buf);
        return (vec![target], sub);
    }
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
    let base = if matches!(stem, "lib" | "main" | "mod") { dir.to_path_buf() } else { dir.join(stem) };
    let sub = base.join(&m.name);
    (vec![base.join(format!("{}.rs", m.name)), sub.join("mod.rs")], Some(sub))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_cfg_test_items() {
        let src = r#"
            fn keep() {}
            #[cfg(test)]
            mod tests { fn gone() {} }
            #[test]
            fn also_gone() {}
            impl X { #[test] fn t() {} fn k() {} }
        "#;
        let p = Project::from_sources([("lib.rs", src)], CrateInfo::default(), false);
        let file = &p.files[0];
        assert_eq!(file.ast.items.len(), 2);
        let p = Project::from_sources([("lib.rs", src)], CrateInfo::default(), true);
        assert_eq!(p.files[0].ast.items.len(), 4);
    }

    #[test]
    fn inner_cfg_test_attribute_marks_whole_file() {
        let src = "#![cfg(test)]\nfn helper() {}\n";
        let p = Project::from_sources([("test.rs", src)], CrateInfo::default(), false);
        assert!(p.files[0].ast.items.is_empty());
        let p = Project::from_sources([("test.rs", src)], CrateInfo::default(), true);
        assert_eq!(p.files[0].ast.items.len(), 1);
    }

    #[test]
    fn reports_parse_errors_with_location() {
        let p = Project::from_sources([("bad.rs", "fn x( {")], CrateInfo::default(), false);
        assert!(p.files.is_empty());
        assert_eq!(p.failures.len(), 1);
        assert_eq!(p.failures[0].file, "bad.rs");
        assert!(p.failures[0].line.is_some());
    }

    #[test]
    fn drops_out_of_line_test_modules() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("lib.rs"), "#[cfg(test)]\nmod test;\nmod storage;\n#[cfg(test)]\nmod tests;\n").unwrap();
        fs::write(src.join("test.rs"), "fn t() {}").unwrap();
        fs::create_dir_all(src.join("tests")).unwrap();
        fs::write(src.join("tests/mod.rs"), "mod helpers;").unwrap();
        fs::write(src.join("tests/helpers.rs"), "fn h() {}").unwrap();
        fs::write(src.join("storage.rs"), "fn s() {}").unwrap();
        let p = Project::load(&[d.path().to_path_buf()], &DiscoverOptions::default()).unwrap();
        let mut names: Vec<_> =
            p.files.iter().map(|f| f.path.file_name().unwrap().to_string_lossy().to_string()).collect();
        names.sort();
        assert_eq!(names, vec!["lib.rs", "storage.rs"]);
    }
}
