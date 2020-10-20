from sklearn import datasets
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split

if __name__ == "__main__":
    print("Using linear regression with Iris dataset")
    iris = datasets.load_iris()
    X = iris.data
    y = iris.target

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.30, random_state=40)

    regressor = LinearRegression(fit_intercept=False, normalize=False)
    regressor.fit(X_train, y_train)

    print(regressor.coef_)