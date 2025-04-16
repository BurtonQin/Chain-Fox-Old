use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AtomicityViolationDiagnosis {
    pub atomic: String,
    // pub(crate) atomic_reader: String,
    // pub atomic_writer: String,
}
