# -*- coding: utf-8 -*-
import numpy as np 
import pandas as pd
from sklearn.decomposition import PCA
from sklearn import preprocessing, feature_extraction, metrics
from sklearn.linear_model import SGDClassifier
import joblib

class IDS:
    def __init__(self):
        """ Load dataset and preprocess """
        self.train_data_from_text = open('kddcup.data_10_percent_corrected', 'r')
        self.test_data_from_text = open('corrected', 'r')

        columns = ['Duration', 'protocol_type', 'Service', 'Flag', 'src_bytes', 'dst_bytes', 'Land', 'wrong_fragment', 'Urgent', 'Hot', 
                   'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 
                   'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'Count', 'srv_count', 'serror_rate', 'srv_serror_rate', 
                   'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 
                   'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 
                   'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'Class']

        # Read dataset
        self.class_train = pd.read_csv(self.train_data_from_text, quotechar=',', skipinitialspace=True, names=columns)
        self.class_test = pd.read_csv(self.test_data_from_text, quotechar=',', skipinitialspace=True, names=columns)

        # Convert class labels to 'normal' and 'attack'
        self.class_train['Class'] = self.class_train['Class'].apply(lambda x: 'normal' if x == 'normal.' else 'attack')
        self.class_test['Class'] = self.class_test['Class'].apply(lambda x: 'normal' if x == 'normal.' else 'attack')

        # Encode categorical features
        self.attribute_encoder = feature_extraction.DictVectorizer(sparse=False)
        self.label_encoder = preprocessing.LabelEncoder()

        self.train_data_dataframe = self.attribute_encoder.fit_transform(self.class_train.iloc[:, :-1].to_dict(orient='records'))
        self.train_target_dataframe = self.label_encoder.fit_transform(self.class_train.iloc[:, -1])

        self.test_data_dataframe = self.attribute_encoder.transform(self.class_test.iloc[:, :-1].to_dict(orient='records'))
        self.test_target_dataframe = self.label_encoder.transform(self.class_test.iloc[:, -1])

        print("Train Data Dimensions Without Feature Selection:", self.train_data_dataframe.shape)
        print("Test Data Dimensions Without Feature Selection:", self.test_data_dataframe.shape)

    def feature_reduction(self):
        """ Apply PCA for feature reduction """
        pca = PCA(n_components=27)  # Ensure consistent PCA components
        self.feature_reducted_train_data = pca.fit_transform(self.train_data_dataframe)  
        self.feature_reducted_test_data = pca.transform(self.test_data_dataframe)

        print("Train Data Dimensions With Feature Selection:", self.feature_reducted_train_data.shape)
        print("Test Data Dimensions With Feature Selection:", self.feature_reducted_test_data.shape)

    def normalizing_datasets(self):
        """ Normalize datasets using StandardScaler """
        standard_scaler = preprocessing.StandardScaler()
        self.train_data_scaled_normalized = pd.DataFrame(standard_scaler.fit_transform(self.feature_reducted_train_data))
        self.test_data_scaled_normalized = pd.DataFrame(standard_scaler.transform(self.feature_reducted_test_data))

    def svm_with_third_party(self):
        """ Train SVM using SGDClassifier """
        print("Training SVM model...")

        svm_object = SGDClassifier(loss="hinge", max_iter=1000, tol=1e-3)

        # Train the SVM model
        svm_object.fit(self.train_data_scaled_normalized, self.train_target_dataframe)

        # Save trained model
        joblib.dump(svm_object, "svm_model.pkl")
        print("✅ SVM Model saved as svm_model.pkl for real-time detection.")

# Run IDS
ids = IDS()
ids.feature_reduction()
ids.normalizing_datasets()
ids.svm_with_third_party()
