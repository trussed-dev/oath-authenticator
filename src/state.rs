#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    // at startup, trussed is not callable yet.
    // moreover, when worst comes to worst, filesystems are not available
    persistent: Option<Persistent>,
    pub runtime: Runtime,
    // temporary "state", to be removed again
    // pub hack: Hack,
    // trussed: RefCell<Trussed<S>>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Persistent {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandState {
    ListCredentials(usize),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Runtime {
    pub previously: Option<CommandState>,
}
