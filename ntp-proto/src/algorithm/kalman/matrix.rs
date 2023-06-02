use std::ops::{Add, Mul, Sub};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Matrix<const N: usize, const M: usize> {
    data: [[f64; M]; N],
}

pub type Vector<const N: usize> = Matrix<N, 1>;

impl<const N: usize, const M: usize> Matrix<N, M> {
    pub fn new(data: [[f64; M]; N]) -> Self {
        Matrix { data }
    }

    pub fn transpose(self) -> Matrix<M, N> {
        Matrix {
            data: std::array::from_fn(|i| std::array::from_fn(|j| self.data[j][i])),
        }
    }

    pub fn entry(&self, i: usize, j: usize) -> f64 {
        assert!(i < N && j < M);
        self.data[i][j]
    }
}

impl<const N: usize> Vector<N> {
    pub fn new_vector(data: [f64; N]) -> Self {
        Self {
            data: std::array::from_fn(|i| std::array::from_fn(|_| data[i])),
        }
    }

    pub fn ventry(&self, i: usize) -> f64 {
        self.data[i][0]
    }

    pub fn inner(&self, rhs: Vector<N>) -> f64 {
        (0..N).map(|i| self.data[i][0] * rhs.data[i][0]).sum()
    }
}

impl<const N: usize> Matrix<N, N> {
    pub fn symmetrize(self) -> Self {
        Matrix {
            data: std::array::from_fn(|i| {
                std::array::from_fn(|j| (self.data[i][j] + self.data[j][i]) / 2.)
            }),
        }
    }

    pub fn unit() -> Self {
        Matrix {
            data: std::array::from_fn(|i| std::array::from_fn(|j| if i == j { 1.0 } else { 0.0 })),
        }
    }
}

impl Matrix<1, 1> {
    pub fn inverse(self) -> Self {
        Matrix {
            data: [[1. / self.data[0][0]]],
        }
    }

    pub fn determinant(self) -> f64 {
        self.data[0][0]
    }
}

impl Matrix<2, 2> {
    pub fn inverse(self) -> Self {
        let d = 1. / (self.data[0][0] * self.data[1][1] - self.data[0][1] * self.data[1][0]);
        Matrix {
            data: [
                [d * self.data[1][1], -d * self.data[0][1]],
                [-d * self.data[1][0], d * self.data[0][0]],
            ],
        }
    }

    pub fn determinant(self) -> f64 {
        self.data[0][0] * self.data[1][1] - self.data[0][1] * self.data[1][0]
    }
}

impl<const N: usize, const M: usize> std::fmt::Display for Matrix<N, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for i in 0..N {
            for j in 0..M {
                if j != 0 {
                    f.write_str(" ")?;
                }
                f.write_fmt(format_args!("{:>14.10}", self.data[i][j]))?;
            }
            if i != N - 1 {
                f.write_str("\n")?;
            }
        }

        Ok(())
    }
}

impl<const K: usize, const N: usize, const M: usize> Mul<Matrix<K, M>> for Matrix<N, K> {
    type Output = Matrix<N, M>;

    fn mul(self, rhs: Matrix<K, M>) -> Self::Output {
        Matrix {
            data: std::array::from_fn(|i| {
                std::array::from_fn(|j| (0..K).map(|k| self.data[i][k] * rhs.data[k][j]).sum())
            }),
        }
    }
}

impl<const N: usize, const M: usize> Mul<Matrix<N, M>> for f64 {
    type Output = Matrix<N, M>;

    fn mul(self, rhs: Matrix<N, M>) -> Self::Output {
        Matrix {
            data: std::array::from_fn(|i| std::array::from_fn(|j| self * rhs.data[i][j])),
        }
    }
}

impl<const N: usize, const M: usize> Add<Matrix<N, M>> for Matrix<N, M> {
    type Output = Matrix<N, M>;

    fn add(self, rhs: Matrix<N, M>) -> Self::Output {
        Matrix {
            data: std::array::from_fn(|i| {
                std::array::from_fn(|j| self.data[i][j] + rhs.data[i][j])
            }),
        }
    }
}

impl<const N: usize, const M: usize> Sub<Matrix<N, M>> for Matrix<N, M> {
    type Output = Matrix<N, M>;

    fn sub(self, rhs: Matrix<N, M>) -> Self::Output {
        Matrix {
            data: std::array::from_fn(|i| {
                std::array::from_fn(|j| self.data[i][j] - rhs.data[i][j])
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matrix_mul() {
        let a = Matrix::new([[1., 2.], [3., 4.]]);
        let b = Matrix::new([[5., 6.], [7., 8.]]);
        let c = Matrix::new([[19., 22.], [43., 50.]]);

        assert_eq!(c, a * b);
    }

    #[test]
    fn test_matrix_vector_mul() {
        let a = Matrix::new([[1., 2.], [3., 4.]]);
        let b = Vector::new_vector([5., 6.]);
        let c = Vector::new_vector([17., 39.]);

        assert_eq!(c, a * b);
    }

    #[test]
    fn test_matrix_inverse() {
        let a = Matrix::new([[1., 1.], [1., 2.]]);
        let b = a.inverse();

        assert_eq!(a * b, Matrix::unit());
    }

    #[test]
    fn test_matrix_transpose() {
        let a = Matrix::new([[1., 1.], [0., 1.]]);
        let b = Matrix::new([[1., 0.], [1., 1.]]);

        assert_eq!(a.transpose(), b);
        assert_eq!(b.transpose(), a);
    }

    #[test]
    fn test_matrix_add() {
        let a = Matrix::new([[1., 0.], [0., 1.]]);
        let b = Matrix::new([[0., -1.], [-1., 0.]]);
        let c = Matrix::new([[1., -1.], [-1., 1.]]);

        assert_eq!(a + b, c);
    }

    #[test]
    fn test_matrix_sub() {
        let a = Matrix::new([[1., 0.], [0., 1.]]);
        let b = Matrix::new([[0., 1.], [1., 0.]]);
        let c = Matrix::new([[1., -1.], [-1., 1.]]);

        assert_eq!(a - b, c);
    }

    #[test]
    fn test_vector_add() {
        let a = Vector::new_vector([1., 0.]);
        let b = Vector::new_vector([0., -1.]);
        let c = Vector::new_vector([1., -1.]);

        assert_eq!(a + b, c);
    }

    #[test]
    fn test_vector_sub() {
        let a = Vector::new_vector([1., 0.]);
        let b = Vector::new_vector([0., 1.]);
        let c = Vector::new_vector([1., -1.]);

        assert_eq!(a - b, c);
    }

    #[test]
    fn test_matrix_rendering() {
        let a = Matrix::new([[1.0, 2.0], [3.0, 4.0]]);
        assert_eq!(
            format!("{a}"),
            "  1.0000000000   2.0000000000\n  3.0000000000   4.0000000000"
        );
    }

    #[test]
    fn test_vector_rendering() {
        let a = Vector::new_vector([5.0, 6.0]);
        assert_eq!(format!("{a}"), "  5.0000000000\n  6.0000000000");
    }
}
