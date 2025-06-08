use anyhow::{Context, Result};
use clap::Parser;
use pyo3::prelude::*;
use pyo3::types::{PyList, PyModule};
use std::ffi::CString;

#[derive(Parser)]
#[command(author, version, about = "PyO3 CLI with auto‐pip‐install")]
struct Args {
    #[arg(short, long)]
    text: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // 1) Python paketlerini kontrol et & pip ile yükle
    Python::with_gil(|py| -> PyResult<()> {
        if PyModule::import(py, "transformers").is_err() {
            // python3 yorumlayıcısını çağır
            let exe = "python3";
            // pip komut argümanları
            let pip_args = ["-m", "pip", "install", "--upgrade", "pip", "setuptools", "transformers", "torch"];
            // ["python3", "-m", "pip", ...]
            let mut cmd = vec![exe];
            cmd.extend(&pip_args);
            let args_py = PyList::new(py, &cmd)?;
            let subprocess = PyModule::import(py, "subprocess")?;
            subprocess.call_method1("run", (args_py,))?;
        }
        Ok(())
    })
        .context("Failed to install Python dependencies")?;

    // 2) Gömülü Python backend'i çağır
    let (label, score): (String, f32) = Python::with_gil(|py| -> PyResult<_> {
        // Get the Python code from the embedded file
        let code_str = include_str!("../../../py_engine.py");
        
        // Create CString values for all parameters
        let code = CString::new(code_str).unwrap();
        let filename = CString::new("py_engine.py").unwrap();
        let module_name = CString::new("py_engine").unwrap();
        
        // Use from_code method with CStr parameters
        let module = PyModule::from_code(
            py,
            code.as_c_str(),
            filename.as_c_str(),
            module_name.as_c_str(),
        )?;
        
        module.getattr("predict")?
            .call1((args.text.as_str(),))?
            .extract()
    })?;

    println!("Label: {}, Score: {:.4}", label, score);
    Ok(())
}
