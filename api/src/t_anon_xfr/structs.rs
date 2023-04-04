
/// An auditor’s memo that accurately describes contents of the transactions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TAxfrAuditorMemo(Vec<u8>);