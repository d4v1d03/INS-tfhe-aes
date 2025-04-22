use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::ops::Not;
use std::sync::Arc;
use tfhe::boolean::prelude::*;

/// This struct represents the operands that can be used in the BooleanExpr
///
/// As we construct the boolean-tree from only True and False as the base operands, the final boolean expression will contain only True and False
/// and the selector bits (Bit0, Bit1, Bit2, Bit3, Bit4, Bit5, Bit6, Bit7) and their negations.
///
/// As operands form the leaves of the boolean expression tree, they are of stage value 0.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Operand {
    True,
    False,
    Bit0,
    NotBit0,
    Bit1,
    NotBit1,
    Bit2,
    NotBit2,
    Bit3,
    NotBit3,
    Bit4,
    NotBit4,
    Bit5,
    NotBit5,
    Bit6,
    NotBit6,
    Bit7,
    NotBit7,
}

impl Not for Operand {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            Operand::True => Operand::False,
            Operand::False => Operand::True,
            Operand::Bit0 => Operand::NotBit0,
            Operand::NotBit0 => Operand::Bit0,
            Operand::Bit1 => Operand::NotBit1,
            Operand::NotBit1 => Operand::Bit1,
            Operand::Bit2 => Operand::NotBit2,
            Operand::NotBit2 => Operand::Bit2,
            Operand::Bit3 => Operand::NotBit3,
            Operand::NotBit3 => Operand::Bit3,
            Operand::Bit4 => Operand::NotBit4,
            Operand::NotBit4 => Operand::Bit4,
            Operand::Bit5 => Operand::NotBit5,
            Operand::NotBit5 => Operand::Bit5,
            Operand::Bit6 => Operand::NotBit6,
            Operand::NotBit6 => Operand::Bit6,
            Operand::Bit7 => Operand::NotBit7,
            Operand::NotBit7 => Operand::Bit7,
        }
    }
}

impl From<bool> for Operand {
    fn from(value: bool) -> Self {
        match value {
            true => Operand::True,
            false => Operand::False,
        }
    }
}

impl Operand {
    fn evaluate(&self, bits: &[Ciphertext], server_key: &ServerKey) -> Ciphertext {
        //depreciated method, used for testing purposes
        match self {
            Operand::True => server_key.trivial_encrypt(true),
            Operand::False => server_key.trivial_encrypt(false),
            Operand::Bit0 => bits[0].clone(),
            Operand::NotBit0 => server_key.not(&bits[0]),
            Operand::Bit1 => bits[1].clone(),
            Operand::NotBit1 => server_key.not(&bits[1]),
            Operand::Bit2 => bits[2].clone(),
            Operand::NotBit2 => server_key.not(&bits[2]),
            Operand::Bit3 => bits[3].clone(),
            Operand::NotBit3 => server_key.not(&bits[3]),
            Operand::Bit4 => bits[4].clone(),
            Operand::NotBit4 => server_key.not(&bits[4]),
            Operand::Bit5 => bits[5].clone(),
            Operand::NotBit5 => server_key.not(&bits[5]),
            Operand::Bit6 => bits[6].clone(),
            Operand::NotBit6 => server_key.not(&bits[6]),
            Operand::Bit7 => bits[7].clone(),
            Operand::NotBit7 => server_key.not(&bits[7]),
        }
    }

    pub fn stage(&self) -> u8 {
        0
    }
}

/// This struct represents the boolean expression tree
///
/// The tree is constructed from the base operands as introduced earlier and the logical operators (And, Or, Xor, Mux)
/// The boolean expressions are ordered:
///
/// For example, the expression (A AND B) is equivalent to (B AND A) and as such only one of these should be stored (for hashing purposes).
/// The one to keep is dependant on the ordering of the operands (if A > B or A < B). The same is done for XOR and OR.
///
/// Next, the expression (!A AND !B) is equivalent to !(A OR B) and as such we keep the former, prioritizing the negation of operands than the negation of the whole expression.
/// We then propagate the negation down the tree, ordering the operands as we go. As such the entire structure will be unique.
/// This same negation propagation is done for the Mux operator as well as !MUX(A, B, C) is equivalent to MUX(A, !B, !C).
///
/// The structure of the selector bits ensures that for a MUX(A, B, C), A is always a non-negated operand.
///
/// Stages are also calculated as the height of a node in the tree
///
/// All of the above ensures that we can hash a boolean expression to be looked up in a truth table. Then, we can evaluate the expression in a staged manner, ensuring
/// that we only evaluate the expression once for each unique sub-expression.
///
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BooleanExpr {
    Operand(Operand),
    And(Box<BooleanExpr>, Box<BooleanExpr>),
    Or(Box<BooleanExpr>, Box<BooleanExpr>),
    Xor(Box<BooleanExpr>, Box<BooleanExpr>),
    Mux(Operand, Box<BooleanExpr>, Box<BooleanExpr>),
}

impl Not for BooleanExpr {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            BooleanExpr::Operand(inner) => BooleanExpr::Operand(!inner),
            BooleanExpr::And(inner_0, inner_1) => BooleanExpr::ordered_or(!*inner_0, !*inner_1),
            BooleanExpr::Or(inner_0, inner_1) => BooleanExpr::ordered_and(!*inner_0, !*inner_1),
            BooleanExpr::Xor(inner_0, inner_1) => BooleanExpr::ordered_xor(!*inner_0, *inner_1),
            BooleanExpr::Mux(mux, inner_0, inner_1) => {
                BooleanExpr::Mux(mux, Box::new(!*inner_0), Box::new(!*inner_1))
            }
        }
    }
}

impl BooleanExpr {
    // This function reduces the number of MUX in the expression tree if for MUX(A, B, C), B == true
    fn mux_left_true(mux: &Operand, right: &BooleanExpr) -> BooleanExpr {
        match right {
            BooleanExpr::Operand(Operand::True) => BooleanExpr::Operand(Operand::True),
            BooleanExpr::Operand(Operand::False) => BooleanExpr::Operand(*mux),
            _ => BooleanExpr::ordered_or(BooleanExpr::Operand(*mux), right.clone()),
        }
    }

    // This function reduces the number of MUX in the expression tree if for MUX(A, B, C), B == false
    fn mux_left_false(mux: &Operand, right: &BooleanExpr) -> BooleanExpr {
        match right {
            BooleanExpr::Operand(Operand::True) => BooleanExpr::Operand(!*mux),
            BooleanExpr::Operand(Operand::False) => BooleanExpr::Operand(Operand::False),
            _ => BooleanExpr::ordered_and(BooleanExpr::Operand(!*mux), right.clone()),
        }
    }

    // This function reduces the number of MUX in the expression tree if for MUX(A, B, C), B == X
    fn mux_left_x(mux: &Operand, left: &BooleanExpr, right: &BooleanExpr) -> BooleanExpr {
        match right {
            BooleanExpr::Operand(Operand::True) => Self::mux_left_true(&!*mux, left),
            BooleanExpr::Operand(Operand::False) => Self::mux_left_false(&!*mux, left),
            _ if left == right => left.clone(),
            _ if *left == !right.clone() => {
                BooleanExpr::ordered_xor(BooleanExpr::Operand(!*mux), left.clone())
            }
            _ => BooleanExpr::Mux(*mux, Box::new(left.clone()), Box::new(right.clone())),
        }
    }

    // This function reduces the number of MUX in the expression tree
    fn mux(mux: &Operand, left: &BooleanExpr, right: &BooleanExpr) -> BooleanExpr {
        match left {
            BooleanExpr::Operand(Operand::True) => Self::mux_left_true(mux, right),
            BooleanExpr::Operand(Operand::False) => Self::mux_left_false(mux, right),
            _ => Self::mux_left_x(mux, left, right),
        }
    }

    fn order_expr(op_1: BooleanExpr, op_2: BooleanExpr) -> (BooleanExpr, BooleanExpr) {
        if op_1 < op_2 {
            (op_1, op_2)
        } else {
            (op_2, op_1)
        }
    }

    fn ordered_xor(op_1: BooleanExpr, op_2: BooleanExpr) -> BooleanExpr {
        let (left, right) = BooleanExpr::order_expr(op_1, op_2);
        BooleanExpr::Xor(Box::new(left), Box::new(right))
    }

    fn ordered_and(op_1: BooleanExpr, op_2: BooleanExpr) -> BooleanExpr {
        let (left, right) = BooleanExpr::order_expr(op_1, op_2);
        BooleanExpr::And(Box::new(left), Box::new(right))
    }

    fn ordered_or(op_1: BooleanExpr, op_2: BooleanExpr) -> BooleanExpr {
        let (left, right) = BooleanExpr::order_expr(op_1, op_2);
        BooleanExpr::Or(Box::new(left), Box::new(right))
    }

    // This function reduces the number of MUX in the expression tree by calling the functions mux (mux_left_true, mux_left_false and mux_left_x) above
    pub fn reduce_mux(items: &Vec<BooleanExpr>) -> BooleanExpr {
        assert!(
            items.len() & (items.len() - 1) == 0,
            "Input was not a power of 2! It was {:?}",
            items.len()
        );

        if items.len() == 0 {
            return BooleanExpr::Operand(Operand::True);
        }

        if items.len() == 1 {
            return items[0].clone();
        }

        let operands = [
            Operand::Bit0,
            Operand::Bit1,
            Operand::Bit2,
            Operand::Bit3,
            Operand::Bit4,
            Operand::Bit5,
            Operand::Bit6,
            Operand::Bit7,
        ];

        let size_log_2: usize =
            (usize::BITS as i32 - (items.len().leading_zeros() as i32)) as usize;

        let result = operands[..size_log_2 - 1]
            .iter()
            .fold(items.clone(), |acc, &operand| {
                acc.array_chunks::<2>()
                    .map(|x| Self::mux(&operand, &x[0], &x[1]))
                    .collect::<Vec<_>>()
            });

        assert!(result.len() == 1, "Something went wrong with the fold");

        result[0].clone()
    }

    pub fn evaluate(
        // Depreciated method, used for testing purposes
        &self,
        bits: &[Ciphertext],
        server_key: &ServerKey,
        visited: Arc<DashMap<BooleanExpr, Ciphertext>>,
    ) -> Ciphertext {
        assert!(bits.len() == 8, "BITS LENGTH IS INCORRECT");

        if visited.contains_key(self) {
            return visited
                .get(self)
                .expect("The DashMap should contain the current Expr")
                .clone();
        }

        let evaluated_expr = match self {
            BooleanExpr::Operand(op) => op.evaluate(bits, server_key),
            BooleanExpr::And(op_1, op_2) => server_key.and(
                &(op_1).evaluate(bits, server_key, visited.clone()),
                &op_2.evaluate(bits, server_key, visited.clone()),
            ),
            BooleanExpr::Or(op_1, op_2) => server_key.or(
                &(op_1).evaluate(bits, server_key, visited.clone()),
                &op_2.evaluate(bits, server_key, visited.clone()),
            ),
            BooleanExpr::Xor(op_1, op_2) => server_key.xor(
                &(op_1).evaluate(bits, server_key, visited.clone()),
                &op_2.evaluate(bits, server_key, visited.clone()),
            ),
            BooleanExpr::Mux(mux, op_1, op_2) => server_key.mux(
                &mux.evaluate(bits, server_key),
                &(op_1).evaluate(bits, server_key, visited.clone()),
                &op_2.evaluate(bits, server_key, visited.clone()),
            ),
        };

        visited.insert(self.clone(), evaluated_expr.clone());
        evaluated_expr
    }

    pub fn from_bool_vec(items: &[bool]) -> Vec<BooleanExpr> {
        items.into_iter().map(|&x| BooleanExpr::from(x)).collect()
    }

    pub fn stage(&self) -> u8 {
        // Helps calculate the height of a node in the tree, thus giving their stage
        match self {
            BooleanExpr::Operand(op) => op.stage(),
            BooleanExpr::And(lhs, rhs) => std::cmp::max(lhs.stage(), rhs.stage()) + 1,
            BooleanExpr::Or(lhs, rhs) => std::cmp::max(lhs.stage(), rhs.stage()) + 1,
            BooleanExpr::Xor(lhs, rhs) => std::cmp::max(lhs.stage(), rhs.stage()) + 1,
            BooleanExpr::Mux(_, lhs, rhs) => std::cmp::max(lhs.stage(), rhs.stage()) + 1,
        }
    }

    pub fn to_hashset(&self, hashset: &mut HashSet<BooleanExpr>) {
        hashset.insert(self.clone());
        match self {
            BooleanExpr::Operand(_) => {
                hashset.insert(self.clone());
            }
            BooleanExpr::And(lhs, rhs) => {
                lhs.to_hashset(hashset);
                rhs.to_hashset(hashset);
            }
            BooleanExpr::Or(lhs, rhs) => {
                lhs.to_hashset(hashset);
                rhs.to_hashset(hashset);
            }
            BooleanExpr::Xor(lhs, rhs) => {
                lhs.to_hashset(hashset);
                rhs.to_hashset(hashset);
            }
            BooleanExpr::Mux(_, lhs, rhs) => {
                lhs.to_hashset(hashset);
                rhs.to_hashset(hashset);
            }
        }
    }

    #[inline(always)]
    pub fn evaluate_stage<'a>(
        // Depreciated method, used for testing purposes
        &'a self,
        server_key: &'a ServerKey,
        operands: Arc<DashMap<Operand, Ciphertext>>,
        inc_hashmap: Arc<DashMap<BooleanExpr, Option<Ciphertext>>>,
        out_hashmap: Arc<DashMap<BooleanExpr, Option<Ciphertext>>>,
    ) -> Box<dyn FnOnce() -> () + 'a> {
        match self {
            BooleanExpr::Operand(op) => {
                let operand = operands
                    .get(op)
                    .expect("Operand not in hashmap")
                    .value()
                    .clone();
                Box::new(move || {
                    out_hashmap.insert(self.clone(), Some(operand.clone()));
                })
            }
            BooleanExpr::And(op_1, op_2) => {
                let operand_1 = inc_hashmap
                    .get(op_1)
                    .expect("Operand 1 not in hashmap")
                    .value()
                    .as_ref()
                    .expect("Value should exist")
                    .clone();
                let operand_2 = inc_hashmap
                    .get(op_2)
                    .expect("Operand 2 not in hashmap")
                    .value()
                    .as_ref()
                    .expect("Value should exist")
                    .clone();
                Box::new(move || {
                    out_hashmap.insert(self.clone(), Some(server_key.and(&operand_1, &operand_2)));
                })
            }
            BooleanExpr::Or(op_1, op_2) => {
                let operand_1 = inc_hashmap
                    .get(op_1)
                    .expect("Operand 1 not in hashmap")
                    .value()
                    .as_ref()
                    .expect("Value should exist")
                    .clone();
                let operand_2 = inc_hashmap
                    .get(op_2)
                    .expect("Operand 2 not in hashmap")
                    .value()
                    .as_ref()
                    .expect("Value should exist")
                    .clone();
                Box::new(move || {
                    out_hashmap.insert(self.clone(), Some(server_key.or(&operand_1, &operand_2)));
                })
            }
            BooleanExpr::Xor(op_1, op_2) => {
                let operand_1 = inc_hashmap
                    .get(op_1)
                    .expect("Operand 1 not in hashmap")
                    .value()
                    .as_ref()
                    .expect("Value should exist")
                    .clone();
                let operand_2 = inc_hashmap
                    .get(op_2)
                    .expect("Operand 2 not in hashmap")
                    .value()
                    .as_ref()
                    .expect("Value should exist")
                    .clone();
                Box::new(move || {
                    out_hashmap.insert(self.clone(), Some(server_key.xor(&operand_1, &operand_2)));
                })
            }
            BooleanExpr::Mux(mux, op_1, op_2) => {
                let mux_ = operands
                    .get(mux)
                    .expect("Mux not in hashmap")
                    .value()
                    .clone();
                let operand_1 = inc_hashmap
                    .get(op_1)
                    .expect("Operand 1 not in hashmap")
                    .value()
                    .as_ref()
                    .expect("Value should exist")
                    .clone();
                let operand_2 = inc_hashmap
                    .get(op_2)
                    .expect("Operand 2 not in hashmap")
                    .value()
                    .as_ref()
                    .expect("Value should exist")
                    .clone();
                Box::new(move || {
                    out_hashmap.insert(
                        self.clone(),
                        Some(server_key.mux(&mux_, &operand_1, &operand_2)),
                    );
                })
            }
        }
    }

    #[inline(always)]
    pub fn evaluate_stage_return(
        // Depreicated method, used for testing purposes
        &self,
        server_key: &ServerKey,
        operands: Arc<DashMap<Operand, Ciphertext>>,
        inc_hashmap: Arc<DashMap<BooleanExpr, Ciphertext>>,
    ) -> Ciphertext {
        match self {
            BooleanExpr::Operand(op) => operands
                .get(op)
                .expect("Operand not in hashmap")
                .value()
                .clone(),
            BooleanExpr::And(op_1, op_2) => server_key.and(
                inc_hashmap
                    .get(op_1)
                    .expect("Operand 1 not in hashmap")
                    .value(),
                inc_hashmap
                    .get(op_2)
                    .expect("Operand 2 not in hashmap")
                    .value(),
            ),
            BooleanExpr::Or(op_1, op_2) => server_key.or(
                inc_hashmap
                    .get(op_1)
                    .expect("Operand 1 not in hashmap")
                    .value(),
                inc_hashmap
                    .get(op_2)
                    .expect("Operand 2 not in hashmap")
                    .value(),
            ),
            BooleanExpr::Xor(op_1, op_2) => server_key.xor(
                inc_hashmap
                    .get(op_1)
                    .expect("Operand 1 not in hashmap")
                    .value(),
                inc_hashmap
                    .get(op_2)
                    .expect("Operand 2 not in hashmap")
                    .value(),
            ),
            BooleanExpr::Mux(mux, op_1, op_2) => server_key.mux(
                operands.get(mux).expect("Mux not in hashmap").value(),
                inc_hashmap
                    .get(op_1)
                    .expect("Operand 1 not in hashmap")
                    .value(),
                inc_hashmap
                    .get(op_2)
                    .expect("Operand 2 not in hashmap")
                    .value(),
            ),
        }
    }
}

impl From<bool> for BooleanExpr {
    fn from(value: bool) -> Self {
        BooleanExpr::Operand(value.into())
    }
}
use std::cmp::Ordering;

impl PartialOrd for Operand {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Operand {
    fn cmp(&self, other: &Self) -> Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

impl BooleanExpr {
    fn discriminant(&self) -> u8 {
        match self {
            BooleanExpr::Operand(_) => 0,
            BooleanExpr::And(_, _) => 1,
            BooleanExpr::Or(_, _) => 2,
            BooleanExpr::Xor(_, _) => 3,
            BooleanExpr::Mux(_, _, _) => 4,
        }
    }
}

impl PartialOrd for BooleanExpr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BooleanExpr {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare discriminants first
        let self_disc = self.discriminant();
        let other_disc = other.discriminant();
        match self_disc.cmp(&other_disc) {
            Ordering::Equal => {
                // Compare content based on the type
                match (self, other) {
                    (BooleanExpr::Operand(a), BooleanExpr::Operand(b)) => a.cmp(b),
                    (BooleanExpr::And(lhs1, rhs1), BooleanExpr::And(lhs2, rhs2))
                    | (BooleanExpr::Or(lhs1, rhs1), BooleanExpr::Or(lhs2, rhs2))
                    | (BooleanExpr::Xor(lhs1, rhs1), BooleanExpr::Xor(lhs2, rhs2)) => {
                        lhs1.cmp(lhs2).then_with(|| rhs1.cmp(rhs2))
                    }
                    (BooleanExpr::Mux(op1, lhs1, rhs1), BooleanExpr::Mux(op2, lhs2, rhs2)) => op1
                        .cmp(op2)
                        .then_with(|| lhs1.cmp(lhs2))
                        .then_with(|| rhs1.cmp(rhs2)),
                    _ => Ordering::Equal,
                }
            }
            other_ordering => other_ordering,
        }
    }
}

impl Hash for Operand {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Use the discriminant of the enum for a basic hash
        std::mem::discriminant(self).hash(state);
    }
}

impl Hash for BooleanExpr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            BooleanExpr::Operand(op) => {
                0.hash(state); // Discriminant for Operand
                op.hash(state);
            }
            BooleanExpr::And(lhs, rhs) => {
                1.hash(state); // Discriminant for And
                lhs.hash(state);
                rhs.hash(state);
            }
            BooleanExpr::Or(lhs, rhs) => {
                2.hash(state); // Discriminant for Or
                lhs.hash(state);
                rhs.hash(state);
            }
            BooleanExpr::Xor(lhs, rhs) => {
                3.hash(state); // Discriminant for Xor
                lhs.hash(state);
                rhs.hash(state);
            }
            BooleanExpr::Mux(op, t_expr, f_expr) => {
                4.hash(state); // Discriminant for Mux
                op.hash(state);
                t_expr.hash(state);
                f_expr.hash(state);
            }
        }
    }
}

/// This struct allows us to evaluate a boolean expression in a staged manner by encapsulating 2-3 Cipertexts in a Vec and then
/// allowing rayon to evaluate the expression in parallel.
pub struct Runnable {
    bool_expr: BooleanExpr,
    operands: Vec<Ciphertext>,
}

impl Runnable {
    pub fn new(
        operands_: &HashMap<Operand, Ciphertext>,
        hashmap: &HashMap<BooleanExpr, Ciphertext>,
        bool_expr: BooleanExpr,
    ) -> Self {
        let mut operands: Vec<_> = Vec::with_capacity(3);

        match &bool_expr {
            BooleanExpr::Operand(op) => operands.push(operands_.get(&op).unwrap().clone()),
            BooleanExpr::And(op1, op2) => {
                operands.push(hashmap.get(&op1).unwrap().clone());
                operands.push(hashmap.get(&op2).unwrap().clone());
            }
            BooleanExpr::Or(op1, op2) => {
                operands.push(hashmap.get(&op1).unwrap().clone());
                operands.push(hashmap.get(&op2).unwrap().clone());
            }
            BooleanExpr::Xor(op1, op2) => {
                operands.push(hashmap.get(&op1).unwrap().clone());
                operands.push(hashmap.get(&op2).unwrap().clone());
            }
            BooleanExpr::Mux(mux, op1, op2) => {
                operands.push(operands_.get(&mux).unwrap().clone());
                operands.push(hashmap.get(&op1).unwrap().clone());
                operands.push(hashmap.get(&op2).unwrap().clone());
            }
        };

        Self {
            bool_expr,
            operands: operands.try_into().unwrap(),
        }
    }
    pub fn run(&self, server_key: &ServerKey) -> Ciphertext {
        match self.bool_expr {
            BooleanExpr::Operand(_) => self.operands[0].clone(),
            BooleanExpr::And(_, _) => server_key.and(&self.operands[0], &self.operands[1]),
            BooleanExpr::Or(_, _) => server_key.or(&self.operands[0], &self.operands[1]),
            BooleanExpr::Xor(_, _) => server_key.xor(&self.operands[0], &self.operands[1]),
            BooleanExpr::Mux(_, _, _) => {
                server_key.mux(&self.operands[0], &self.operands[1], &self.operands[2])
            }
        }
    }
}

#[cfg(test)]
pub mod tests {

    use std::time::{Duration, Instant};

    use super::*;
    use rayon::prelude::*;
    use tfhe::boolean::gen_keys;

    pub fn bool_to_ciphertext(booleans: &[bool], client_key: &ClientKey) -> Vec<Ciphertext> {
        booleans.iter().map(|&x| client_key.encrypt(x)).collect()
    }

    fn u128_to_bool(mut x: u128, bits: usize) -> Vec<bool> {
        let mut res = vec![];
        for _ in 0..bits {
            res.push(x & 1 != 0);
            x >>= 1;
        }

        res
    }

    fn u256_to_bool(x: u128, y: u128, bits: usize) -> Vec<bool> {
        let mut first_half = u128_to_bool(x, bits / 2);
        let second_half = u128_to_bool(y, bits / 2);

        first_half.extend(second_half);

        first_half
    }

    fn generate_bits(count: u32) -> Vec<Box<Vec<bool>>> {
        let mut res = vec![];
        let base: u128 = 2;
        for x in 0..base.pow(count) {
            let intermediate_res = u128_to_bool(x, count as usize);
            res.push(Box::new(intermediate_res));
        }
        res
    }

    fn mux(mux: bool, left: bool, right: bool) -> bool {
        if mux { left } else { right }
    }

    fn clear_mux_eval(bool_bits: &[bool], truth_table: &[bool]) -> bool {
        assert!(
            truth_table.len() & (truth_table.len() - 1) == 0,
            "Input was not a power of 2!"
        );

        if truth_table.len() == 0 {
            return true;
        }

        if truth_table.len() == 1 {
            return truth_table[0];
        }

        let size_log_2: usize =
            (usize::BITS as i32 - (truth_table.len().leading_zeros() as i32)) as usize;

        let result =
            bool_bits[..size_log_2 - 1]
                .iter()
                .fold(truth_table.to_vec(), |acc, &operand| {
                    acc.array_chunks::<2>()
                        .map(|x| mux(operand, x[0], x[1]))
                        .collect::<Vec<_>>()
                });

        assert!(result.len() == 1, "Something went wrong with the fold");

        result[0]
    }

    #[test]
    fn test_mux_true_1() {
        let expr = BooleanExpr::from_bool_vec(&vec![true]);
        let result = BooleanExpr::reduce_mux(&expr);
        assert_eq!(result, BooleanExpr::Operand(Operand::True));
    }

    #[test]
    fn test_mux_true_2() {
        let expr = BooleanExpr::from_bool_vec(&vec![true, true]);
        let result = BooleanExpr::reduce_mux(&expr);
        assert_eq!(result, BooleanExpr::Operand(Operand::True));
    }

    #[test]
    fn test_mux_true_4() {
        let expr = BooleanExpr::from_bool_vec(&vec![true, true, true, true]);
        let result = BooleanExpr::reduce_mux(&expr);
        assert_eq!(result, BooleanExpr::Operand(Operand::True));
    }

    #[test]
    fn test_mux_true_false() {
        let expr = BooleanExpr::from_bool_vec(&vec![true, false]);
        let result = BooleanExpr::reduce_mux(&expr);
        assert_eq!(result, BooleanExpr::Operand(Operand::Bit0));
    }

    #[test]
    fn test_mux_true_false_true_false() {
        let expr = BooleanExpr::from_bool_vec(&vec![true, false, true, false]);
        let result = BooleanExpr::reduce_mux(&expr);
        assert_eq!(result, BooleanExpr::Operand(Operand::Bit0));
    }

    #[test]
    fn test_mux_true_false_false_false() {
        let expr = BooleanExpr::from_bool_vec(&vec![true, false, false, false]);
        let result = BooleanExpr::reduce_mux(&expr);
        assert_eq!(
            result,
            BooleanExpr::And(
                Box::new(BooleanExpr::Operand(Operand::Bit0)),
                Box::new(BooleanExpr::Operand(Operand::Bit1))
            )
        );
    }

    #[test]
    fn test_evaluate_true() {
        let (client_key, server_key) = gen_keys();
        let bits = bool_to_ciphertext(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );

        let expr = BooleanExpr::from_bool_vec(&vec![true]);
        let result_expr = BooleanExpr::reduce_mux(&expr);
        let enc_result = result_expr.evaluate(&bits, &server_key, Arc::new(DashMap::new()));

        assert_eq!(client_key.decrypt(&enc_result), true);
    }

    #[test]
    fn test_evaluate_false() {
        let (client_key, server_key) = gen_keys();
        let bits = bool_to_ciphertext(
            &vec![true, true, true, true, true, true, true, true],
            &client_key,
        );

        let expr = BooleanExpr::from_bool_vec(&vec![false]);
        let result_expr = BooleanExpr::reduce_mux(&expr);
        let enc_result = result_expr.evaluate(&bits, &server_key, Arc::new(DashMap::new()));

        assert_eq!(client_key.decrypt(&enc_result), false);
    }

    #[test]
    fn test_evaluate_level_0_true_false() {
        let (client_key, server_key) = gen_keys();
        let expr = BooleanExpr::from_bool_vec(&vec![true, false]);
        let result_expr = BooleanExpr::reduce_mux(&expr);

        for bool_bits in generate_bits(8).into_iter() {
            let bits = bool_to_ciphertext(&bool_bits, &client_key);
            let enc_result = result_expr.evaluate(&bits, &server_key, Arc::new(DashMap::new()));
            assert_eq!(client_key.decrypt(&enc_result), bool_bits[0]);
        }
    }

    #[test]
    fn test_evaluate_level_0_false_true() {
        let (client_key, server_key) = gen_keys();
        let expr = BooleanExpr::from_bool_vec(&vec![false, true]);
        let result_expr = BooleanExpr::reduce_mux(&expr);

        for bool_bits in generate_bits(8).into_iter() {
            let bits = bool_to_ciphertext(&bool_bits, &client_key);
            let enc_result = result_expr.evaluate(&bits, &server_key, Arc::new(DashMap::new()));
            assert_eq!(client_key.decrypt(&enc_result), !bool_bits[0]);
        }
    }

    #[test]
    fn test_evaluate_level_0_true_true() {
        let (client_key, server_key) = gen_keys();
        let expr = BooleanExpr::from_bool_vec(&vec![true, true]);
        let result_expr = BooleanExpr::reduce_mux(&expr);

        for bool_bits in generate_bits(8).into_iter() {
            let bits = bool_to_ciphertext(&bool_bits, &client_key);
            let enc_result = result_expr.evaluate(&bits, &server_key, Arc::new(DashMap::new()));
            assert_eq!(client_key.decrypt(&enc_result), true);
        }
    }

    #[test]
    fn test_evaluate_level_0_false_false() {
        let (client_key, server_key) = gen_keys();
        let truth_table = vec![false, false];
        let expr = BooleanExpr::from_bool_vec(&truth_table);
        let result_expr = BooleanExpr::reduce_mux(&expr);

        for bool_bits in generate_bits(8).into_iter() {
            let bits = bool_to_ciphertext(&bool_bits, &client_key);
            let enc_result = result_expr.evaluate(&bits, &server_key, Arc::new(DashMap::new()));

            let clear_result = clear_mux_eval(&bool_bits, &truth_table);
            assert_eq!(client_key.decrypt(&enc_result), clear_result);
        }
    }

    #[test]
    fn test_evaluate_level_0() {
        let (client_key, server_key) = gen_keys();

        for truth_table in generate_bits(2) {
            let expr = BooleanExpr::from_bool_vec(&truth_table);
            let result_expr = BooleanExpr::reduce_mux(&expr);

            for bool_bits in generate_bits(8).into_iter() {
                let bits = bool_to_ciphertext(&bool_bits, &client_key);
                let enc_result = result_expr.evaluate(&bits, &server_key, Arc::new(DashMap::new()));

                let clear_result = clear_mux_eval(&bool_bits, &truth_table);
                assert_eq!(
                    client_key.decrypt(&enc_result),
                    clear_result,
                    "BITS: {:?}, TRUTH_TABLE: {:?}",
                    bool_bits,
                    truth_table
                );
            }
        }
    }

    #[test]
    fn test_evaluate_level_1() {
        let (client_key, server_key) = gen_keys();

        for truth_table in generate_bits(4) {
            let expr = BooleanExpr::from_bool_vec(&truth_table);
            let result_expr = BooleanExpr::reduce_mux(&expr);

            for bool_bits in generate_bits(8).into_iter() {
                let bits = bool_to_ciphertext(&bool_bits, &client_key);
                let enc_result = result_expr.evaluate(&bits, &server_key, Arc::new(DashMap::new()));

                let clear_result = clear_mux_eval(&bool_bits, &truth_table);
                assert_eq!(
                    client_key.decrypt(&enc_result),
                    clear_result,
                    "BITS: {:?}, TRUTH_TABLE: {:?}",
                    bool_bits,
                    truth_table
                );
            }
        }
    }

    #[test]
    fn test_evaluate_level_2() {
        let (client_key, server_key) = gen_keys();
        let truth_tables = vec![Box::new(vec![
            true, false, true, true, false, false, false, true,
        ])];
        for truth_table in truth_tables {
            let expr = BooleanExpr::from_bool_vec(&truth_table);
            let result_expr = BooleanExpr::reduce_mux(&expr);

            for bool_bits in generate_bits(8)[128..].into_iter() {
                let bits = bool_to_ciphertext(&bool_bits, &client_key);
                let enc_result = result_expr.evaluate(&bits, &server_key, Arc::new(DashMap::new()));

                let clear_result = clear_mux_eval(&bool_bits, &truth_table);
                assert_eq!(
                    client_key.decrypt(&enc_result),
                    clear_result,
                    "BITS: {:?}, TRUTH_TABLE: {:?}",
                    bool_bits,
                    truth_table
                );
            }
        }
    }

    #[test]
    fn test_evaluate_level_5() {
        let (client_key, server_key) = gen_keys();
        let truth_tables = vec![u128_to_bool(23456789 as u128, 64 as usize)];
        for truth_table in truth_tables {
            let expr = BooleanExpr::from_bool_vec(&truth_table);
            let result_expr = BooleanExpr::reduce_mux(&expr);

            for bool_bits in generate_bits(8)[..1].into_iter() {
                let bits = bool_to_ciphertext(&bool_bits, &client_key);
                let enc_result = result_expr.evaluate(&bits, &server_key, Arc::new(DashMap::new()));

                let clear_result = clear_mux_eval(&bool_bits, &truth_table);
                assert_eq!(
                    client_key.decrypt(&enc_result),
                    clear_result,
                    "BITS: {:?}, TRUTH_TABLE: {:?}",
                    bool_bits,
                    truth_table
                );
            }
        }
    }

    #[test]
    fn test_evaluate_level_7() {
        let (client_key, server_key) = gen_keys();
        let truth_tables = vec![u256_to_bool(23456789 as u128, 234567 as u128, 256 as usize)];
        for truth_table in truth_tables {
            let expr = BooleanExpr::from_bool_vec(&truth_table);
            let result_expr = BooleanExpr::reduce_mux(&expr);

            let mut total = Duration::new(0, 0);
            for bool_bits in generate_bits(8)[0..100].into_iter() {
                let bits = bool_to_ciphertext(&bool_bits, &client_key);
                let start = Instant::now();
                let enc_result = result_expr.evaluate(&bits, &server_key, Arc::new(DashMap::new()));
                total += start.elapsed();

                let clear_result = clear_mux_eval(&bool_bits, &truth_table);
                assert_eq!(
                    client_key.decrypt(&enc_result),
                    clear_result,
                    "BITS: {:?}, TRUTH_TABLE: {:?}",
                    bool_bits,
                    truth_table
                );
            }

            println!("TIME TAKEN: {:?}", total / 100);
        }
    }

    #[test]
    fn test_evaluate_stage() {
        let num_threads = rayon::current_num_threads();
        println!("Rayon is using {} threads", num_threads);
        // Setup server key and operands
        let (client_key, server_key) = gen_keys();
        // Assuming ServerKey has a new() method
        let mut operands = HashMap::new();

        // Create some dummy Ciphertext values
        let bit0 = client_key.encrypt(true);
        let bit1 = client_key.encrypt(false);
        let bit2 = client_key.encrypt(true);
        let bit3 = client_key.encrypt(false);
        // Insert operands and intermediate values into the hashmaps

        operands.insert(Operand::Bit0, bit0.clone());
        operands.insert(Operand::Bit1, bit1.clone());
        operands.insert(Operand::Bit2, bit2.clone());
        operands.insert(Operand::Bit3, bit3.clone());

        let expr1 = BooleanExpr::Operand(Operand::Bit1);
        let expr2 = BooleanExpr::Operand(Operand::Bit2);

        let and_expr = BooleanExpr::And(Box::new(expr1.clone()), Box::new(expr2.clone()));
        let or_expr = BooleanExpr::Or(Box::new(expr1.clone()), Box::new(expr2.clone()));
        let xor_expr = BooleanExpr::Xor(Box::new(expr1.clone()), Box::new(expr2.clone()));
        let mux_expr_0 = BooleanExpr::Mux(
            Operand::Bit0,
            Box::new(expr1.clone()),
            Box::new(expr2.clone()),
        );
        let mux_expr_1 = BooleanExpr::Mux(
            Operand::Bit1,
            Box::new(expr1.clone()),
            Box::new(expr2.clone()),
        );
        let mux_expr_2 = BooleanExpr::Mux(
            Operand::Bit2,
            Box::new(expr1.clone()),
            Box::new(expr2.clone()),
        );
        let mux_expr_3 = BooleanExpr::Mux(
            Operand::Bit3,
            Box::new(expr1.clone()),
            Box::new(expr2.clone()),
        );
        let mux_expr_4 = BooleanExpr::Mux(
            Operand::Bit0,
            Box::new(expr2.clone()),
            Box::new(expr1.clone()),
        );
        let mux_expr_5 = BooleanExpr::Mux(
            Operand::Bit1,
            Box::new(expr2.clone()),
            Box::new(expr1.clone()),
        );
        let mux_expr_6 = BooleanExpr::Mux(
            Operand::Bit2,
            Box::new(expr2.clone()),
            Box::new(expr1.clone()),
        );
        let mux_expr_7 = BooleanExpr::Mux(
            Operand::Bit3,
            Box::new(expr2.clone()),
            Box::new(expr1.clone()),
        );

        let test_suite: [BooleanExpr; 2] = [expr1.clone(), expr2.clone()];

        let start = Instant::now();
        let mut hash_map: HashMap<BooleanExpr, Ciphertext> = HashMap::new();
        hash_map = test_suite
            .into_iter()
            .map(|expr| (expr.clone(), Runnable::new(&operands, &hash_map, expr)))
            .collect::<Vec<_>>()
            .into_par_iter()
            .map_with(&server_key, |server_key, (expr, runnable)| {
                (expr, runnable.run(server_key))
            })
            .collect::<HashMap<_, _>>();

        println!("TIME TAKEN: {:?}", start.elapsed());

        let stage_1: [BooleanExpr; 128] = [
            mux_expr_0.clone(),
            mux_expr_1.clone(),
            mux_expr_2.clone(),
            mux_expr_3.clone(),
            mux_expr_4.clone(),
            mux_expr_5.clone(),
            mux_expr_6.clone(),
            mux_expr_7.clone(),
            mux_expr_0.clone(),
            mux_expr_1.clone(),
            mux_expr_2.clone(),
            mux_expr_3.clone(),
            mux_expr_4.clone(),
            mux_expr_5.clone(),
            mux_expr_6.clone(),
            mux_expr_7.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            or_expr.clone(),
            or_expr.clone(),
            or_expr.clone(),
            or_expr.clone(),
            xor_expr.clone(),
            xor_expr.clone(),
            xor_expr.clone(),
            xor_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            mux_expr_0.clone(),
            mux_expr_1.clone(),
            mux_expr_2.clone(),
            mux_expr_3.clone(),
            mux_expr_4.clone(),
            mux_expr_5.clone(),
            mux_expr_6.clone(),
            mux_expr_7.clone(),
            mux_expr_0.clone(),
            mux_expr_1.clone(),
            mux_expr_2.clone(),
            mux_expr_3.clone(),
            mux_expr_4.clone(),
            mux_expr_5.clone(),
            mux_expr_6.clone(),
            mux_expr_7.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            or_expr.clone(),
            or_expr.clone(),
            or_expr.clone(),
            or_expr.clone(),
            xor_expr.clone(),
            xor_expr.clone(),
            xor_expr.clone(),
            xor_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            mux_expr_0.clone(),
            mux_expr_1.clone(),
            mux_expr_2.clone(),
            mux_expr_3.clone(),
            mux_expr_4.clone(),
            mux_expr_5.clone(),
            mux_expr_6.clone(),
            mux_expr_7.clone(),
            mux_expr_0.clone(),
            mux_expr_1.clone(),
            mux_expr_2.clone(),
            mux_expr_3.clone(),
            mux_expr_4.clone(),
            mux_expr_5.clone(),
            mux_expr_6.clone(),
            mux_expr_7.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            or_expr.clone(),
            or_expr.clone(),
            or_expr.clone(),
            or_expr.clone(),
            xor_expr.clone(),
            xor_expr.clone(),
            xor_expr.clone(),
            xor_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            mux_expr_0.clone(),
            mux_expr_1.clone(),
            mux_expr_2.clone(),
            mux_expr_3.clone(),
            mux_expr_4.clone(),
            mux_expr_5.clone(),
            mux_expr_6.clone(),
            mux_expr_7.clone(),
            mux_expr_0.clone(),
            mux_expr_1.clone(),
            mux_expr_2.clone(),
            mux_expr_3.clone(),
            mux_expr_4.clone(),
            mux_expr_5.clone(),
            mux_expr_6.clone(),
            mux_expr_7.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            or_expr.clone(),
            or_expr.clone(),
            or_expr.clone(),
            or_expr.clone(),
            xor_expr.clone(),
            xor_expr.clone(),
            xor_expr.clone(),
            xor_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
            and_expr.clone(),
        ];

        let start = Instant::now();
        let stage_3 = stage_1
            .into_iter()
            .map(|expr| (expr.clone(), Runnable::new(&operands, &hash_map, expr)))
            .collect::<Vec<_>>();

        println!("TIME TAKEN: {:?}", start.elapsed());
        let start = Instant::now();

        hash_map = stage_3
            .into_par_iter()
            .map_with(&server_key, |server_key, (expr, runnable)| {
                (expr, runnable.run(server_key))
            })
            .collect::<HashMap<_, _>>();

        println!("TIME TAKEN: {:?}", start.elapsed());

        let decrypt_0 = client_key.decrypt(&bit0);
        let decrypt_1 = client_key.decrypt(&bit1);
        let decrypt_2 = client_key.decrypt(&bit2);
        let decrypt_3 = client_key.decrypt(&bit3);

        // Check if the result is in the out_hashmap
        assert!(hash_map.contains_key(&mux_expr_0));
        let result = hash_map.get(&mux_expr_0).unwrap();
        let expected_result = (decrypt_0 & decrypt_1) | ((!decrypt_0) & decrypt_2);
        assert_eq!(client_key.decrypt(result), expected_result);

        assert!(hash_map.contains_key(&mux_expr_1));
        let result = hash_map.get(&mux_expr_1).unwrap();
        let expected_result = (decrypt_1 & decrypt_1) | (!decrypt_1 & decrypt_2);
        assert_eq!(client_key.decrypt(result), expected_result);

        assert!(hash_map.contains_key(&mux_expr_2));
        let result = hash_map.get(&mux_expr_2).unwrap();
        let expected_result = (decrypt_2 & decrypt_1) | (!decrypt_2 & decrypt_2);
        assert_eq!(client_key.decrypt(result), expected_result);

        assert!(hash_map.contains_key(&mux_expr_3));
        let result = hash_map.get(&mux_expr_3).unwrap();
        let expected_result = (decrypt_3 & decrypt_1) | (!decrypt_3 & decrypt_2);
        assert_eq!(client_key.decrypt(result), expected_result);

        assert!(hash_map.contains_key(&mux_expr_4));
        let result = hash_map.get(&mux_expr_4).unwrap();
        let expected_result = (decrypt_0 & decrypt_2) | (!decrypt_0 & decrypt_1);
        assert_eq!(client_key.decrypt(result), expected_result);

        assert!(hash_map.contains_key(&mux_expr_5));
        let result = hash_map.get(&mux_expr_5).unwrap();
        let expected_result = (decrypt_1 & decrypt_2) | (!decrypt_1 & decrypt_1);
        assert_eq!(client_key.decrypt(result), expected_result);
    }
}
