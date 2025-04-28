#![allow(non_camel_case_types)]
use crate::secret::VisibleSideEffectFree;

#[derive(Clone, Default)]
pub struct Label_A {}
#[derive(Clone, Default)]
pub struct Label_B {}
#[derive(Clone, Default)]
pub struct Label_C {}

// Three mid-level secrecy labels for each combination of Label_A, Label_B, Label_C
#[derive(Clone, Default)]
pub struct Label_AB {}
#[derive(Clone, Default)]
pub struct Label_BC {}
#[derive(Clone, Default)]
pub struct Label_AC {}

// Bottom (Label_Empty) and top (Label_ABC) level secrecy labels
#[derive(Clone, Default)]
pub struct Label_Empty {}
#[derive(Clone, Default)]
pub struct Label_ABC {}

unsafe impl Label for Label_Empty {}
unsafe impl Label for Label_A {}
unsafe impl Label for Label_B {}
unsafe impl Label for Label_C {}
unsafe impl Label for Label_AB {}
unsafe impl Label for Label_AC {}
unsafe impl Label for Label_BC {}
unsafe impl Label for Label_ABC {}

// TODO: If Label isn't declared unsafe, this is still allowed.
// Why is the supertrait (VisibleSideEffectFree) of a safe trait allowed by the compiler??
pub unsafe trait Label: Default + VisibleSideEffectFree /*+ UnwindSafe*/ {}

// Define the secrecy level lattice using this trait
pub trait MoreSecretThan<T>: Label {}

// encode lattice relationships
impl<T: Label> MoreSecretThan<T> for T {} // reflexive property

impl MoreSecretThan<Label_Empty> for Label_A {}
impl MoreSecretThan<Label_Empty> for Label_B {}
impl MoreSecretThan<Label_Empty> for Label_C {}
impl MoreSecretThan<Label_Empty> for Label_AB {}
impl MoreSecretThan<Label_Empty> for Label_BC {}
impl MoreSecretThan<Label_Empty> for Label_AC {}
impl MoreSecretThan<Label_Empty> for Label_ABC {}

impl MoreSecretThan<Label_A> for Label_AB {}
impl MoreSecretThan<Label_A> for Label_AC {}
impl MoreSecretThan<Label_A> for Label_ABC {}

impl MoreSecretThan<Label_B> for Label_AB {}
impl MoreSecretThan<Label_B> for Label_BC {}
impl MoreSecretThan<Label_B> for Label_ABC {}

impl MoreSecretThan<Label_C> for Label_BC {}
impl MoreSecretThan<Label_C> for Label_AC {}
impl MoreSecretThan<Label_C> for Label_ABC {}

impl MoreSecretThan<Label_AB> for Label_ABC {}
impl MoreSecretThan<Label_BC> for Label_ABC {}
impl MoreSecretThan<Label_AC> for Label_ABC {}
