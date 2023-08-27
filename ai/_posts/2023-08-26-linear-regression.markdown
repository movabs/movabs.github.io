---
layout: post
title:  "The Art of Linearity"
date:   2023-08-26 08:47:30 +0100
category: ai
---

# Unraveling Data Dynamics through Linear Regression and Cost Function Minimization

## Abstract:

Linear regression, a foundational statistical technique, constitutes a vital instrument for modeling intricate 
relationships between dependent and independent variables within the empirical realm. This expository inquiry 
embarks on an incisive exploration of linear regression's underpinnings, encompassing its mathematical essence, 
optimization strategies, and evaluative paradigms. We unveil the cardinal role of linear regression in diverse domains, 
propounding it as an analytical cornerstone for predicting, elucidating, and discerning inter-variable dynamics. 
Our exposition delves into the derivation of the fundamental formula, elucidating the contextual significance of the 
intercept and slope parameters. Subsequently, we embark on a rigorous dissection of the cost function, 
a pivotal construct instrumental in the estimation of model parameters, grounded in the Mean Squared Error $$(MSE)$$ paradigm. 
An incisive exposition of gradient descent as a quintessential optimization algorithm unfolds, 
traversing its iterative mechanics towards optimizing parameter space.

The pursuit of model fidelity unfurls through meticulous evaluation via $$R-squared$$, $$Root Mean Squared Error (RMSE)$$, 
and $$Residual Standard Error (RSE)$$ metrics, thereby culminating in a comprehensive model appraisal. 
By syncretizing mathematical rigor with pragmatic utility, this work furnishes an in-depth comprehension of 
linear regression's mechanics, manifesting its quintessence as an indelible analytical methodology within the scientific and practical domains.

## 1. Introduction

#### Linear Regression: A Fundamental Analysis of Linear Modeling

Linear regression, a core statistical technique, serves as an invaluable tool for modeling the relationships 
between two types of variables: dependent $$(Y)$$ and independent $$(X)$$. The idea behind it is to find a straight line
that best fits the data points.

Think of it as a versatile tool used in various fields, like predicting sales, assessing risks, and making 
financial forecasts. It's like finding a formula that describes how one thing affects another.
The basic formula looks like this:

$$ Y=θ0+θ1X $$

Where:

- $$ Y $$: signifies the dependent variable under consideration or the value requiring prediction.
- $$ θ0 $$: commonly referred to as Theta 0, represents the intercept of the linear regression line.
- $$ θ1 $$: denoted as Theta 1, corresponds to the slope of the line.
- $$ X $$: designates the independent variable associated with the analysis.

To make predictions, we need to figure out the optimal values for $$ θ0 $$ and $$ θ1 $$ to establish
a linear relationship that encapsulates the inherent dynamics between the variables.


## 2. Graphical Interpretation of Linear Regression

![Linear regression scatter](/assets/linear_regression_scatter.png)

As you see in the plotted graph. When we draw a line that fits these points best,
it has two important parts: the slope and the starting point (Intercept).

### 2.1. Understanding the Slope and Intercept:

The slope encapsulates the change in the dependent variable $$ Y $$ for a unit alteration in the independent variable $$ X $$. 
Meanwhile, the intercept marks the starting point of the regression line on the vertical axis.

### 2.2. The Line as a Map:

This line isn't just a line; it's like a map. Given an $$ X $$ value, locating its intersection with the line enables
the estimation of the corresponding $$ Y $$ value. But remember, there's a bit of unpredictability, like random deviations,
between the real $$ Y $$ value and our prediction.

### 2.3. Minimizing Errors:

## 3. The Cost Function: Determining Optimal Model Parameters

### 3.1. The Role of the Cost Function:

Let's dive into a key concept that helps us figure out the line that fits our data points just right.
This section delves into the intricacies of the cost function, a critical mathematical construct that guides 
the estimation of these parameters.

### 3.2. Definition of the Cost Function:

Think of the cost function as a kind of compass that tells us which way to go to find the perfect line. 
It measures how far our predicted outcomes are from the real data points. In the context of linear regression, 
the $$ Mean Squared Error (MSE) $$ emerges as a prevalent choice for the cost function. 
This function calculates the average squared difference between the predicted $$ y $$ values and the observed $$ y $$ values.

### 3.3. The MSE Calculation:

Imagine we're looking at a line y=mx+by=mx+b where mm represents the slope and bb signifies the intercept. 
For every point we have, we calculate the difference between the real $$ y $$ value and what our line predicts. 
Then we square this difference to make everything positive. 
We do this for all the points and then average these squared differences. That's the MSE.

### 3.4. Utilizing the Cost Function for Optimization:

The cornerstone of linear regression optimization is the minimization of the cost function. 
We do this by tweaking the values of $$θ0$$ and $$θ1$$ using methods like gradient descent. 
The idea is to keep adjusting these numbers iteratively until the cost function is as small as it can be. 
The objective is to reach a point in the parameter space where the cost function attains its minimum value. 
When we reach this point, we've found the line that matches our data the best, which is the whole point of linear regression.

## 4. Gradient Descent: Enhancing Cost Function Minimization

### 4.1. The Objective of Optimization:

When it comes to linear regression, the central ambition is to identify the parameter values $$θ0$$ and $$θ1$$
that yield the smallest possible cost function $$(MSE)$$. We do this by making the cost function $$(MSE)$$
as small as possible. This cost function measures how much our predictions differ from the actual data. 
To optimize the model, this cost function must be minimized across all data points.

### 4.2. How Gradient Descent Works:

Imagine we start with some random values for $$θ0$$ and $$θ1$$. The magic of gradient descent is that it 
helps us find better values for these parameters step by step. It's like taking small steps downhill 
to reach the lowest point, which is where our cost function is the smallest.

### 4.3. The Mathematics of Gradient Descent:

The essence of gradient descent lies in computing the gradient of the cost function with respect to the model parameters.
It's all about finding the steep slope that goes uphill in our cost function. 
Then we go in the opposite direction (downhill) by subtracting this slope multiplied by a learning rate
from our $$θ0$$ and $$θ1$$ values. This slowly guides us to advance toward the minimum of the cost function.

### 4.4. Gradient Descent Iterations:

The iterative updates of $$θ0$$ and $$θ1$$ are guided by the following expressions:

$$ θ0 = θ0 - \alpha \cdot \frac{2}{N} \sum_{i=1}^{N} (pred\_y - y_i) $$

$$ θ1 = θ1 - \alpha \cdot \frac{2}{N} \sum_{i=1}^{N} (pred\_y - y_i) \cdot X_i $$

Where:

- $$ θ0 $$: represents the intercept of the linear regression line.
- $$ θ1 $$: corresponds to the slope of the line.
- $$ \alpha $$: denotes the learning rate, which controls the size of the steps we take downhill.
- $$ N $$: signifies the number of data points.
- $$ pred\_y $$: represents the predicted $$ y $$ value.
- $$ y_i $$: denotes the real $$ y $$ value.
- $$ X_i $$: signifies the $$ x $$ value.
- $$ \sum_{i=1}^{N} $$: denotes the summation of all the data points.
- $$ \frac{2}{N} $$: represents the average of the squared differences between the predicted $$ y $$ values and the real $$ y $$ values.
- $$ (pred\_y - y_i) $$: signifies the difference between the predicted $$ y $$ value and the real $$ y $$ value.
- $$ (pred\_y - y_i) \cdot X_i $$: represents the difference between the predicted $$ y $$ value and the real $$ y $$ value multiplied by the $$ x $$ value.
- $$ \sum_{i=1}^{N} (pred\_y - y_i) $$: denotes the summation of all the differences between the predicted $$ y $$ values and the real $$ y $$ values.

### 4.5. Evaluating Model Performance:

Measuring the quality of a linear regression model involves using different tools to see how well our 
predicted outcomes match the real data.

#### 4.5.1. Coefficient of Determination or R-Squared (R2):

Among the arsenal of evaluation tools, the Coefficient of Determination, denoted as $$R-squared (R2)$$, 
occupies a preeminent role. It's like a score that tells us how much of the variation in our data the model can explain. 
$$R2$$ numbers go from 0 to 1. ***The higher the $$R2$$ value, the better our model fits the data***.

##### 4.5.1.1. Mathematical Formulation of R2:

Mathematically, the $$R-squared$$ value is computed as:

$$ R2=1−RSS/TSS $$

Where:
- RSS represents the Residual Sum of Squares, computed as the summation of the squared deviations between 
predicted and actual data points.

$$ RSS = \sum_{i=1}^{N} (yi - θ0 - θ1xi)^2 $$

- TSS corresponds to the Total Sum of Squares, defined as the summation of squared differences between each 
data point and the mean of the response variable.

$$ TSS = \sum_{i=1}^{N} (y_i - \bar{y})^2 $$

## 5. Conclusion and Further Resources

Below is a link to a Python implementation of linear regression.

https://github.com/lenartlola/ft_linear_regression
