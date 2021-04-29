# coding: utf-8

# ## A Machine Learning approach for Malware Detection

# Importing all the required libraries

# In[1]:
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.datasets import load_breast_cancer
from sklearn.model_selection import train_test_split
from collections import defaultdict
import sys,os
import numpy as np
import random
import numpy
from sklearn.externals import joblib
import time
import pickle as pkl
from mpl_toolkits.mplot3d import Axes3D
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from collections import defaultdict

from sklearn.metrics import log_loss,precision_score,recall_score,f1_score,\
                fbeta_score,confusion_matrix

import os
import pandas
import numpy
import pickle
import pefile
from sklearn.externals import joblib
import sklearn.ensemble as ek
from sklearn import  tree, linear_model
import sklearn.model_selection
from sklearn.feature_selection import SelectFromModel

from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import confusion_matrix
from sklearn.pipeline import make_pipeline
from sklearn import preprocessing
from sklearn import svm
from sklearn.linear_model import LinearRegression


# Loading the initial dataset delimited by | 

# In[2]:


dataset = pandas.read_csv('./data.csv',sep='|', low_memory=False)


# In[3]:


dataset.head()


# In[4]:


dataset.describe()


# Number of malicious files vs Legitimate files in the training set

# In[5]:


dataset.groupby(dataset['legitimate']).size()


# Dropping columns like Name of the file, MD5 (message digest) and label

# In[6]:


X = dataset.drop(['Name','md5','legitimate'],axis=1).values
y = dataset['legitimate'].values


# ##### ExtraTreesClassifier
# ExtraTreesClassifier fits a number of randomized decision trees (a.k.a. extra-trees) on various sub-samples of the dataset and use averaging to improve the predictive accuracy and control over-fitting

# In[7]:


extratrees = ek.ExtraTreesClassifier().fit(X,y)
model = SelectFromModel(extratrees, prefit=True)
X_new = model.transform(X)
nbfeatures = X_new.shape[1]


# ExtraTreesClassifier helps in selecting the required features useful for classifying a file as either Malicious or Legitimate
# 
# 14 features are identified as required by ExtraTreesClassifier

#


# ######  Cross Validation
# Cross validation is applied to divide the dataset into random train and test subsets.
# test_size = 0.2 represent the proportion of the dataset to include in the test split 

# In[14]:


X_train, X_test, y_train, y_test = train_test_split(X_new, y ,test_size=0.2)


features = []
index = numpy.argsort(extratrees.feature_importances_)[::-1][:nbfeatures]


# The features identified by ExtraTreesClassifier

# In[10]:


for f in range(nbfeatures):
    print("%d. feature %s (%f)" % (f + 1, dataset.columns[2+index[f]], extratrees.feature_importances_[index[f]]))
    features.append(dataset.columns[2+f])


# Building the below Machine Learning model

# In[12]:

# clf1 = SVC(kernel='linear')#不采用核函数
# clf2 = SVC(kernel='rbf', C=10, gamma=0.0001)#采用高斯核函数
model = {
         "svm linear":SVC(kernel='linear'),
         "svm gauss keinel ":SVC(kernel='rbf', C=10, gamma=0.0001)
}


# Training each of the model with the X_train and testing with X_test.
# The model with best accuracy will be ranked as winner

# In[25]:


results = {}
for algo in model:
    clf = model[algo]
    clf.fit(X_train,y_train)
    score = clf.score(X_test,y_test)
    print ("%s : %s " %(algo, score))
    results[algo] = score


# In[26]:


winner = max(results, key=results.get)


# Saving the model

# In[27]:


joblib.dump(model[winner],'./classifier2.pkl')


# In[28]:


open('./features2.pkl', 'w').write(pickle.dumps(features))


# Calculating the False positive and negative on the dataset

# In[41]:


clf = model[winner]
res = clf.predict(X_new)
mt = confusion_matrix(y, res)
print("False positive rate : %f %%" % ((mt[0][1] / float(sum(mt[0])))*100))
print('False negative rate : %f %%' % ( (mt[1][0] / float(sum(mt[1]))*100)))
