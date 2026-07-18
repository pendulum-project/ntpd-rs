use core::ops::{Add, AddAssign, Index, IndexMut, Mul, Sub, SubAssign};

/// A storage provider for a matrix. Abstracts a dynamically sized array of f64.
///
/// It is explicitly allowed for the  [`AsRef`] and [`AsMut`] implementations to
/// return references to larger arrays, so long as the additional length is always
/// identical and modification to the additional entries does not matter.
pub trait MatrixStorage: AsRef<[f64]> + AsMut<[f64]> {
    /// Create a new instance of the storage.
    fn new(len: usize, data: impl FnMut(usize) -> f64) -> Self;
}

#[cfg(feature = "std")]
impl MatrixStorage for std::boxed::Box<[f64]> {
    fn new(len: usize, data: impl FnMut(usize) -> f64) -> Self {
        (0..len).map(data).collect()
    }
}

impl<const N: usize> MatrixStorage for [f64; N] {
    fn new(len: usize, mut data: impl FnMut(usize) -> f64) -> Self {
        assert!(len <= N);
        core::array::from_fn(|index| if index < len { data(index) } else { 0.0 })
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
/// A simple class for computing with matrices.
///
/// Indexing into these matrices is done with tuples indicating row first, and then the column.
pub struct Matrix<Storage> {
    rows: usize,
    cols: usize,
    storage: Storage,
}

impl<Storage> Matrix<Storage> {
    /// Number of rows in the matrix
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Number of columns in the matrix
    pub fn cols(&self) -> usize {
        self.cols
    }
}

impl<Storage: MatrixStorage> Matrix<Storage> {
    /// Create a new matrix, filling the values of the cells using the provided function.
    pub fn new(rows: usize, cols: usize, mut values: impl FnMut(usize, usize) -> f64) -> Self {
        Matrix {
            rows,
            cols,
            storage: Storage::new(rows * cols, |index| values(index / cols, index % cols)),
        }
    }

    pub fn identity(size: usize) -> Self {
        Matrix::new(
            size,
            size,
            |row, column| if row == column { 1.0 } else { 0.0 },
        )
    }

    pub fn zero(rows: usize, cols: usize) -> Self {
        Matrix::new(rows, cols, |_, _| 0.0)
    }

    pub fn transpose(&self) -> Self {
        Matrix::new(self.cols, self.rows, |row, column| self[(column, row)])
    }
}

impl<Storage: MatrixStorage> Index<(usize, usize)> for Matrix<Storage> {
    type Output = f64;

    fn index(&self, (r, c): (usize, usize)) -> &Self::Output {
        assert!(r < self.rows);
        assert!(c < self.cols);
        &self.storage.as_ref()[r * self.cols + c]
    }
}

impl<Storage: MatrixStorage> IndexMut<(usize, usize)> for Matrix<Storage> {
    fn index_mut(&mut self, (r, c): (usize, usize)) -> &mut Self::Output {
        assert!(r < self.rows);
        assert!(c < self.cols);
        &mut self.storage.as_mut()[r * self.cols + c]
    }
}

impl<Storage: MatrixStorage> Add<Matrix<Storage>> for Matrix<Storage> {
    type Output = Matrix<Storage>;

    fn add(self, rhs: Matrix<Storage>) -> Self::Output {
        assert_eq!(self.cols, rhs.cols);
        assert_eq!(self.rows, rhs.rows);

        let lhs = self.storage.as_ref();
        let rhs = rhs.storage.as_ref();

        Matrix {
            rows: self.rows,
            cols: self.cols,
            storage: Storage::new(self.rows * self.cols, |index| lhs[index] + rhs[index]),
        }
    }
}

impl<Storage: MatrixStorage> AddAssign<Matrix<Storage>> for Matrix<Storage> {
    fn add_assign(&mut self, rhs: Matrix<Storage>) {
        assert_eq!(self.cols, rhs.cols);
        assert_eq!(self.rows, rhs.rows);
        let lhs = self.storage.as_mut();
        let rhs = rhs.storage.as_ref();
        for (i, value) in lhs.iter_mut().enumerate() {
            *value += rhs[i];
        }
    }
}

impl<Storage: MatrixStorage> Sub<Matrix<Storage>> for Matrix<Storage> {
    type Output = Matrix<Storage>;

    fn sub(self, rhs: Matrix<Storage>) -> Self::Output {
        assert_eq!(self.cols, rhs.cols);
        assert_eq!(self.rows, rhs.rows);

        let lhs = self.storage.as_ref();
        let rhs = rhs.storage.as_ref();

        Matrix {
            rows: self.rows,
            cols: self.cols,
            storage: Storage::new(self.rows * self.cols, |index| lhs[index] - rhs[index]),
        }
    }
}

impl<Storage: MatrixStorage> SubAssign<Matrix<Storage>> for Matrix<Storage> {
    fn sub_assign(&mut self, rhs: Matrix<Storage>) {
        assert_eq!(self.cols, rhs.cols);
        assert_eq!(self.rows, rhs.rows);
        let lhs = self.storage.as_mut();
        let rhs = rhs.storage.as_ref();
        for (i, value) in lhs.iter_mut().enumerate() {
            *value -= rhs[i];
        }
    }
}

impl<Storage: MatrixStorage> Mul<Matrix<Storage>> for f64 {
    type Output = Matrix<Storage>;

    fn mul(self, rhs: Matrix<Storage>) -> Self::Output {
        let rows = rhs.rows;
        let cols = rhs.cols;
        let rhs = rhs.storage.as_ref();

        Matrix {
            rows,
            cols,
            storage: Storage::new(rows * cols, |index| rhs[index] * self),
        }
    }
}

impl<Storage: MatrixStorage> Mul<f64> for Matrix<Storage> {
    type Output = Matrix<Storage>;

    fn mul(self, rhs: f64) -> Self::Output {
        let lhs = self.storage.as_ref();

        Matrix {
            rows: self.rows,
            cols: self.cols,
            storage: Storage::new(self.rows * self.cols, |index| lhs[index] * rhs),
        }
    }
}

impl<Storage: MatrixStorage> Mul<Matrix<Storage>> for Matrix<Storage> {
    type Output = Matrix<Storage>;

    fn mul(self, rhs: Matrix<Storage>) -> Self::Output {
        assert_eq!(self.cols, rhs.rows);

        let lhs_storage = self.storage.as_ref();
        let rhs_storage = rhs.storage.as_ref();

        Matrix {
            rows: self.rows,
            cols: rhs.cols,
            storage: Storage::new(self.rows * rhs.cols, |index| {
                let r = index / rhs.cols;
                let c = index % rhs.cols;
                (0..self.cols)
                    .map(|k| lhs_storage[r * self.cols + k] * rhs_storage[k * rhs.cols + c])
                    .sum::<f64>()
            }),
        }
    }
}

#[cfg(all(test, feature = "std"))]
#[allow(clippy::cast_precision_loss, reason = "Test code")]
#[allow(clippy::float_cmp, reason = "Test code")]
mod tests {
    use super::Matrix;
    use std::boxed::Box;

    #[test]
    fn test_indexing() {
        let mut matrix = Matrix::<Box<[f64]>>::new(3, 2, |r, c| (r * 100 + c) as f64);

        assert_eq!(matrix[(0, 0)], 0.0);
        assert_eq!(matrix[(1, 0)], 100.0);
        assert_eq!(matrix[(2, 0)], 200.0);
        assert_eq!(matrix[(0, 1)], 1.0);
        assert_eq!(matrix[(1, 1)], 101.0);
        assert_eq!(matrix[(2, 1)], 201.0);

        matrix[(1, 0)] = 50.0;

        assert_eq!(matrix[(0, 0)], 0.0);
        assert_eq!(matrix[(1, 0)], 50.0);
        assert_eq!(matrix[(2, 0)], 200.0);
        assert_eq!(matrix[(0, 1)], 1.0);
        assert_eq!(matrix[(1, 1)], 101.0);
        assert_eq!(matrix[(2, 1)], 201.0);
    }

    #[test]
    fn test_array_storage() {
        let matrix = Matrix::<[f64; 10]>::new(3, 2, |r, c| (r * 100 + c) as f64);

        assert_eq!(matrix[(0, 0)], 0.0);
        assert_eq!(matrix[(1, 0)], 100.0);
        assert_eq!(matrix[(2, 0)], 200.0);
        assert_eq!(matrix[(0, 1)], 1.0);
        assert_eq!(matrix[(1, 1)], 101.0);
        assert_eq!(matrix[(2, 1)], 201.0);
    }

    #[test]
    fn test_add() {
        let mut matrix = Matrix::<Box<[f64]>>::new(2, 3, |r, c| (r * 50 + c * 2) as f64)
            + Matrix::<Box<[f64]>>::new(2, 3, |r, c| (r * 150 + c * 3) as f64);

        assert_eq!(matrix[(0, 0)], 0.0);
        assert_eq!(matrix[(1, 0)], 200.0);
        assert_eq!(matrix[(0, 1)], 5.0);
        assert_eq!(matrix[(1, 1)], 205.0);
        assert_eq!(matrix[(0, 2)], 10.0);
        assert_eq!(matrix[(1, 2)], 210.0);

        matrix += Matrix::<Box<[f64]>>::new(2, 3, |r, c| (r * 75 + c * 4) as f64);

        assert_eq!(matrix[(0, 0)], 0.0);
        assert_eq!(matrix[(1, 0)], 275.0);
        assert_eq!(matrix[(0, 1)], 9.0);
        assert_eq!(matrix[(1, 1)], 284.0);
        assert_eq!(matrix[(0, 2)], 18.0);
        assert_eq!(matrix[(1, 2)], 293.0);
    }

    #[test]
    fn test_sub() {
        let mut matrix = Matrix::<Box<[f64]>>::new(1, 2, |_, c| (100 + 50 * c) as f64)
            - Matrix::<Box<[f64]>>::new(1, 2, |_, c| (15 + 75 * c) as f64);

        assert_eq!(matrix[(0, 0)], 85.0);
        assert_eq!(matrix[(0, 1)], 60.0);

        matrix -= Matrix::<Box<[f64]>>::new(1, 2, |_, _| 9.0);

        assert_eq!(matrix[(0, 0)], 76.0);
        assert_eq!(matrix[(0, 1)], 51.0);
    }

    #[test]
    fn test_mul() {
        let matrix = 2.5 * Matrix::<Box<[f64]>>::new(2, 3, |r, c| (r * 50 + c * 2) as f64);

        assert_eq!(matrix[(0, 0)], 0.0);
        assert_eq!(matrix[(1, 0)], 125.0);
        assert_eq!(matrix[(0, 1)], 5.0);
        assert_eq!(matrix[(1, 1)], 130.0);
        assert_eq!(matrix[(0, 2)], 10.0);
        assert_eq!(matrix[(1, 2)], 135.0);

        let matrix = Matrix::<Box<[f64]>>::new(2, 3, |r, c| (r * 50 + c * 2) as f64) * 2.5;

        assert_eq!(matrix[(0, 0)], 0.0);
        assert_eq!(matrix[(1, 0)], 125.0);
        assert_eq!(matrix[(0, 1)], 5.0);
        assert_eq!(matrix[(1, 1)], 130.0);
        assert_eq!(matrix[(0, 2)], 10.0);
        assert_eq!(matrix[(1, 2)], 135.0);

        let matrix = Matrix::<Box<[f64]>>::new(2, 2, |r, c| if r == c { 0.0 } else { 1.0 })
            * Matrix::<Box<[f64]>>::new(2, 2, |r, c| (r * 2 + c) as f64);

        assert_eq!(matrix[(0, 0)], 2.0);
        assert_eq!(matrix[(0, 1)], 3.0);
        assert_eq!(matrix[(1, 0)], 0.0);
        assert_eq!(matrix[(1, 1)], 1.0);

        let matrix = Matrix::<Box<[f64]>>::new(2, 2, |r, c| (r * 2 + c) as f64)
            * Matrix::<Box<[f64]>>::new(2, 2, |r, c| if r == c { 0.0 } else { 1.0 });

        assert_eq!(matrix[(0, 0)], 1.0);
        assert_eq!(matrix[(0, 1)], 0.0);
        assert_eq!(matrix[(1, 0)], 3.0);
        assert_eq!(matrix[(1, 1)], 2.0);
    }
}
