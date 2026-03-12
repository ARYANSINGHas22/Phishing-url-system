import pickle
import matplotlib.pyplot as plt
import numpy as np

model = pickle.load(open("phishing_model.pkl","rb"))
vectorizer = pickle.load(open("vectorizer.pkl","rb"))

feature_names = vectorizer.get_feature_names_out()

coefficients = model.coef_[0]

top_indices = np.argsort(coefficients)[-20:]

plt.figure(figsize=(10,6))
plt.barh(range(len(top_indices)), coefficients[top_indices])
plt.yticks(range(len(top_indices)), feature_names[top_indices])
plt.title("Top Features for Phishing Detection")

plt.show()