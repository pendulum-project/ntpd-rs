use std::ops::{Add, Mul, Sub};

#[derive(Clone, Copy, PartialEq)]
pub struct Matrix {
    data: [f64; 4],
}

#[derive(Clone, Copy, PartialEq)]
pub struct Vector {
    data: [f64; 2],
}

impl Matrix {
    pub const UNIT: Matrix = Matrix {
        data: [1., 0., 0., 1.],
    };

    pub fn new(a: f64, b: f64, c: f64, d: f64) -> Matrix {
        Matrix { data: [a, b, c, d] }
    }

    pub fn inverse(self) -> Matrix {
        let d = 1. / (self.data[0] * self.data[3] - self.data[1] * self.data[2]);
        Matrix {
            data: [
                d * self.data[3],
                -d * self.data[1],
                -d * self.data[2],
                d * self.data[0],
            ],
        }
    }

    pub fn symmetrize(self) -> Matrix {
        let diag = (self.data[1] + self.data[2]) / 2.;
        Matrix {
            data: [self.data[0], diag, diag, self.data[3]],
        }
    }

    pub fn transpose(self) -> Matrix {
        Matrix {
            data: [self.data[0], self.data[2], self.data[1], self.data[3]],
        }
    }

    pub fn entry(&self, i: usize, j: usize) -> f64 {
        assert!(i < 2 && j < 2);
        self.data[2 * i + j]
    }

    pub fn determinant(&self) -> f64 {
        self.data[0] * self.data[3] - self.data[1] * self.data[2]
    }
}

impl std::fmt::Debug for Matrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Matrix((({:?},{:?}),({:?},{:?})))",
            self.data[0], self.data[1], self.data[2], self.data[3]
        ))
    }
}

impl std::fmt::Display for Matrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:>14.10} {:>14.10}\n{:>14.10} {:>14.10}",
            self.data[0], self.data[1], self.data[2], self.data[3]
        ))
    }
}

impl Vector {
    pub fn new(a: f64, b: f64) -> Vector {
        Vector { data: [a, b] }
    }

    pub fn entry(&self, i: usize) -> f64 {
        self.data[i]
    }

    pub fn inner(&self, rhs: Vector) -> f64 {
        self.data[0] * rhs.data[0] + self.data[1] * rhs.data[1]
    }
}

impl std::fmt::Debug for Vector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Vector(({:?},{:?}))",
            self.data[0], self.data[1]
        ))
    }
}

impl std::fmt::Display for Vector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:>14.10}\n{:>14.10}",
            self.data[0], self.data[1]
        ))
    }
}

impl Mul<Matrix> for Matrix {
    type Output = Matrix;

    fn mul(self, rhs: Self) -> Self::Output {
        Matrix {
            data: [
                self.data[0] * rhs.data[0] + self.data[1] * rhs.data[2],
                self.data[0] * rhs.data[1] + self.data[1] * rhs.data[3],
                self.data[2] * rhs.data[0] + self.data[3] * rhs.data[2],
                self.data[2] * rhs.data[1] + self.data[3] * rhs.data[3],
            ],
        }
    }
}

impl Mul<Vector> for Matrix {
    type Output = Vector;

    fn mul(self, rhs: Vector) -> Self::Output {
        Vector {
            data: [
                self.data[0] * rhs.data[0] + self.data[1] * rhs.data[1],
                self.data[2] * rhs.data[0] + self.data[3] * rhs.data[1],
            ],
        }
    }
}

impl Add for Matrix {
    type Output = Matrix;

    fn add(self, rhs: Self) -> Self::Output {
        Matrix {
            data: [
                self.data[0] + rhs.data[0],
                self.data[1] + rhs.data[1],
                self.data[2] + rhs.data[2],
                self.data[3] + rhs.data[3],
            ],
        }
    }
}

impl Sub for Matrix {
    type Output = Matrix;

    fn sub(self, rhs: Self) -> Self::Output {
        Matrix {
            data: [
                self.data[0] - rhs.data[0],
                self.data[1] - rhs.data[1],
                self.data[2] - rhs.data[2],
                self.data[3] - rhs.data[3],
            ],
        }
    }
}

impl Add for Vector {
    type Output = Vector;

    fn add(self, rhs: Self) -> Self::Output {
        Vector {
            data: [self.data[0] + rhs.data[0], self.data[1] + rhs.data[1]],
        }
    }
}

impl Sub for Vector {
    type Output = Vector;

    fn sub(self, rhs: Self) -> Self::Output {
        Vector {
            data: [self.data[0] - rhs.data[0], self.data[1] - rhs.data[1]],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matrix_mul() {
        let a = Matrix::new(1., 2., 3., 4.);
        let b = Matrix::new(5., 6., 7., 8.);
        let c = Matrix::new(19., 22., 43., 50.);

        assert_eq!(c, a * b);
    }

    #[test]
    fn test_matrix_vector_mul() {
        let a = Matrix::new(1., 2., 3., 4.);
        let b = Vector::new(5., 6.);
        let c = Vector::new(17., 39.);

        assert_eq!(c, a * b);
    }

    #[test]
    fn test_matrix_inverse() {
        let a = Matrix::new(1., 1., 1., 2.);
        let b = a.inverse();

        assert_eq!(a * b, Matrix::UNIT);
    }

    #[test]
    fn test_matrix_transpose() {
        let a = Matrix::new(1., 1., 0., 1.);
        let b = Matrix::new(1., 0., 1., 1.);

        assert_eq!(a.transpose(), b);
        assert_eq!(b.transpose(), a);
    }

    #[test]
    fn test_matrix_add() {
        let a = Matrix::new(1., 0., 0., 1.);
        let b = Matrix::new(0., -1., -1., 0.);
        let c = Matrix::new(1., -1., -1., 1.);

        assert_eq!(a + b, c);
    }

    #[test]
    fn test_matrix_sub() {
        let a = Matrix::new(1., 0., 0., 1.);
        let b = Matrix::new(0., 1., 1., 0.);
        let c = Matrix::new(1., -1., -1., 1.);

        assert_eq!(a - b, c);
    }

    #[test]
    fn test_vector_add() {
        let a = Vector::new(1., 0.);
        let b = Vector::new(0., -1.);
        let c = Vector::new(1., -1.);

        assert_eq!(a + b, c);
    }

    #[test]
    fn test_vector_sub() {
        let a = Vector::new(1., 0.);
        let b = Vector::new(0., 1.);
        let c = Vector::new(1., -1.);

        assert_eq!(a - b, c);
    }

    #[test]
    fn test_matrix_rendering() {
        let a = Matrix::new(1.0, 2.0, 3.0, 4.0);
        assert_eq!(
            format!("{a}"),
            "  1.0000000000   2.0000000000\n  3.0000000000   4.0000000000"
        );
        assert_eq!(format!("{a:?}"), "Matrix(((1.0,2.0),(3.0,4.0)))");
    }

    #[test]
    fn test_vector_rendering() {
        let a = Vector::new(5.0, 6.0);
        assert_eq!(format!("{a}"), "  5.0000000000\n  6.0000000000");
        assert_eq!(format!("{a:?}"), "Vector((5.0,6.0))");
    }
}
