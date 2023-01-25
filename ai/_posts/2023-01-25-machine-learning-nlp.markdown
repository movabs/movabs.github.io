---
layout: default
title:  "Machine Learning NLP - Natural Language Processing"
date:   2023-01-25 07:17:30 +0100
category: ai
---

# Machine Learning NLP

## Intent Classifier:

**A pdf version of this article is available at [here](https://github.com/lenartlola/intent_classifier/blob/main/pdf/machine-learning-NLP.pfd)**

**You can also find the code base on (GitHub)[https://github.com/lenartlola/intent_classifier]**

### 1. Introduction

Natural Language Processing (NLP) is a field of Machine Learning.
It deals with manipulation and processing of natural language by humans,
meaning it allows machines to break down and interpret human language.
It has been applied in various fields in today's technologies such as `translation,
chat-bot, spam filters, search engines, grammar correction, voice assistants,
social media monitoring tools` and even your beloved **ChatGPT**.

The intent classifier is to process the user’s text queries and classify them into categories.
In general, the intent of users is divided into three categories:
1. Informational: the user wants to learn something.
2. Transactional: the user is looking for a specific product or service.
3. Navigational: the user is looking for a specific place.

Determining intent is a specific task that needs special handling using quite different methods.

The key-part of this work is the use of pre-trained word embeddings and specifically
[word2vec](https://en.wikipedia.org/wiki/Word2vec), a technique that uses a neural network model to learn word associations
from a large corpus of text and a neural network called [Long-Short Term Memory (LSTM)](https://en.wikipedia.org/wiki/Long_short-term_memory),
a type of [recurrent neural network (RNN)](https://en.wikipedia.org/wiki/Recurrent_neural_network) capable of learning order dependence in sequence prediction problems.
In RNN output from the last step as input in the current step, which allows our model
to remember information from many previous steps.

### 2. Definitions:

#### 2.1 Tokenization:

The tokenization process is quite a simple technique used almost in every technology,
it consists of splitting some inputs into tokens. We are going to split sentences into a vector of words,
for example the string “Hello, I am Lenart” would be something like this[“hello”, “I”, “am”, “Lenart”] 
allows us to manipulate each word separately more easily.
And also at the end of the day a vector of numbers is all our machine could understand.

#### 2.2 Tokenization:

Stop words are the most common words in any language such as (articles, prepositions, pronouns, conjunctions, etc)
and generally are filtered out before processing because they usually don’t add much information to the text.
Examples of a few stop words in English are “the”, “a”, “an”, “so” etc..
By removing these stop words, we remove the low-level information from our text in order to give more attention
to the most important information.
In fact, we do not always remove the stop words, sometimes they could be important depending on what kind of model
we want to train, for example in a sentimental analysis model, we might not remove the stop words.

Feedback: “This was not good at all.”
Text after removing stop words: “This good”

As you can see it changes a lot! Therefore a good preprocessing should be implemented.

#### 2.3 Stemming:

Stemming is a process of finding out the root of a word. For example “asked” and “ask” are just different tenses
of the same verb. The idea is to convert a word to its stem because words with the same stem mostly describe
the same or relatively close concepts in the text and words can be conflated by using stems.
But again, it does depend on the language as well, for example in the English vocabulary stemming is usually necessary
and other languages, like French lemmatization may be more effective than stemming due to special format of words.

#### 2.4 Lemmatization:

Lemmatization is a more calculated process than stemming. It involves resolving words to their dictionary form.
In fact, a lemma of a word is its dictionary or canonical form. Because lemmatization is more nuanced in this respect,
it requires a little more to actually make work.
For lemmatization to resolve a word to its lemma, it needs to know its part of speech.

### 3. Problem Definition and Dataset Description:

#### 3.1 Problem:

The challenging part of every machine learning task is the generalization of the model,
that is the ability to predict unseen samples. It is a challenge to create a robust model
which can deal with problems from other domains.
For example, words like “from”, “to” are useless in most of the problems such as text,
document, topic classification, but in our problem may carry a big portion of available information.
An easier problem to solve is the queries with restricted freedom of expression that users can use.

#### 3.2 Dataset:

I have been reading many researches regarding this topic from the [“What is left to be understood in ATIS?”](https://www.microsoft.com/en-us/research/wp-content/uploads/2010/12/SLT10.pdf)
to [“Attention-Based Recurrent Neural Network Models for Joint Intent Detection and Slot Filling”](https://arxiv.org/abs/1609.01454)
and most of them,
if not all, seem to use the “ATIS”.
ATIS contains sentences in text that come from audio recording by users queries
who ask for information about flight-related services.

### 4. Approaches

This section would explain the tools and approaches used to solve this problem.

#### 4.1 Tools:

This approach is implemented using Python because of its popularity in the field and the sake of simplicity.
And we will enjoy its richness of libraries.

**Scikit-learn:** a free software machine learning library. It features various classification,
regression and clustering algorithms including support-vector machines, random forests, gradient boosting,
k-means and DBSCAN, and is designed to interoperate with the Python numerical and scientific libraries NumPy and SciPy.

**Natural Language Toolkit:** as its name suggests, it is our ideal tool.
It provides easy-to-use interfaces to over 50 corpora and lexical resources such as WordNet,
along with a suite of text processing libraries for classification, tokenization, stemming, tagging, parsing,
and semantic reasoning, and wrappers for industrial-strength NLP libraries. It is a suitable platform for researchers,
linguists, engineers, students and teachers thanks to hand-on guides introducing programming basics
alongside API documentation. It is also open-source and community driven platform and free.

**Pandas:** when I first heard of panda I was still learning to code and I only coded in C programming language,
for those who come from a language such as C/C++ can feel the power of data types and methods that Panda provides.
It is an open-source library that provides high-performance and easy-to-use data analysis tools and structures
to manipulate data and process it.

**NumPy:** a vital package for Python programmers which contains a powerful n-dimensional array object,
capable of fast linear algebra computations, transformations and random number capabilities.

**Matplotlib:** a library that provides features to create quality figures in a variety of formats
and environments across platforms. It can generate various figures like plots, histograms, bar charts, scatterplots,
pie charts, etc..

#### 4.2 Exploratory Data Analysis:

You may have already realized, we are going to work on data. By data I mean a lot of them.
Therefore, exploring data and datasets is a valuable part of a machine learning task.
It can give a first view of the data, correlations between variables and any useful pattern derived from visualization of available data.
It is an approach to analyzing datasets and extracting their main characteristics.
We are going to analyze the ATIS dataset, drawing plots and analyze normalized mutual information
scores between words and intents to gain interesting insights.

Let's do some analysis, we can download a well labeled dataset [ATIS](https://www.kaggle.com/datasets/siddhadev/ms-cntk-atis) from kaggle.
When I looked at the dataset I noticed a lot of “flight” intent, and a simple script in python such as:

```python
import csv

with open('atis_intents.xls', newline='') as csvfile:
	reader = csv.reader(csvfile, delimiter=' ', quotechar='|')
	n_flight = 0
	n_row = 0
	for row in reader:
    	if 'atis_flight,' in row:
        	n_flight += 1
    	n_row += 1
	print((n_flight / n_row) * 100)
```

Told me that flight intent captures nearly 73.644% of all intents. That was a good starting point.

I then dug more into the dataset and realized that using pandas dataframe would be more sophisticated
to analyze it (I also downloaded the csv file of the dataset instead of the xls, such a dummy mistake!),
but I won’t show all the approaches as I intend to  write another article with techniques on how to dig
and analyze a dataset.

Almost in every text relating task in machine learning, the length of sentences often gives some important information.

#### 4.3 pre-processing:

I first tried to load the dataset and see some nice information:

```python
import pandas as pd
import pickle

with open("atis.train.pkl", "rb") as path:
    	dataset, dicts = pickle.load(path)
	
print("Loaded data:")
print(' samples: {:4d}'.format(len(dataset['query'])))
print(' vocab_size: {:4d}'.format(len(dicts['token_ids'])))
print(' slot count: {:4d}'.format(len(dicts['slot_ids'])))
print(' intent count: {:4d}'.format(len(dicts['intent_ids'])))
```

Here is what we get when running the code:

```python
Loaded data:
 samples: 4978
 vocab_size:  943
 slot count:  129
 intent count:   26
```

Nice! From that result we know that, we have 4978 sentences, 943 vocabulary, 129 slots (more about it later)
and 26 different intents.

The code above simply loads a labeled database, opens it as a stream of byte, then we pickle this stream of byte
and return a vector of array dataset and a dictionary that holds information about all the sentence dicts.

Here is what we have in the dataset:

1. Dataset:
   - slot_labels
   - query
   - intent_labels 

2. Dicts:
   - token_ids 
   - Slot_ids 
   - intent_ids

You can see this by simply putting a print within a loop.

```python
for i in dataset:
	print(i)
	
for i in dicts:
	print(i)
```

Well, now we have a bunch of non-organized data, we should parse these data into proper formats
and create some dataframe using Pandas.

- First we get a dataset and dicts for training and test.
- Get the indexes of each element, we can get this by doing var = dicts[“ids”].
- Get the elements in the dataset, and we can do it by var = dataset[“label”].
- After that we create a list for each of these, I have mapped them and used some lambda tricks.
- And then we create a dataframe from the data we get from the dataset.

This part was quite about pre-processing the data and vectorizing words, 
In the next part I will talk about how to solve the actual problem and explain more about this part.



