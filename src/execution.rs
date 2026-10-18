use std::fmt;

/// A command may have started; callers must not replay these failures implicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionFailure {
    Cancelled,
    SettlementUnknown,
    ObserverTimeout,
}

impl ExecutionFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "command_cancelled",
            Self::SettlementUnknown => "command_settlement_unknown",
            Self::ObserverTimeout => "command_observer_timeout",
        }
    }

    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "command_cancelled" => Ok(Self::Cancelled),
            "command_settlement_unknown" => Ok(Self::SettlementUnknown),
            "command_observer_timeout" => Ok(Self::ObserverTimeout),
            _ => anyhow::bail!("unknown execution failure {value:?}"),
        }
    }
}

impl fmt::Display for ExecutionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for ExecutionFailure {}
