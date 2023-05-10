use noah_algebra::traits::Scalar;

/// Trait for the Shallue-van de Woestijne map
pub trait SW<S: Scalar> {
    /// Constant Z0 of Shallue-van de Woestijne map
    const Z0: S;
    /// Constant Z0 of Shallue-van de Woestijne map
    const C1: S;
    /// Constant Z0 of Shallue-van de Woestijne map
    const C2: S;
    /// Constant Z0 of Shallue-van de Woestijne map
    const C3: S;
    /// Constant Z0 of Shallue-van de Woestijne map
    const C4: S;
    /// Constant Z0 of Shallue-van de Woestijne map
    const C5: S;
    /// Constant Z0 of Shallue-van de Woestijne map
    const C6: S;
}
