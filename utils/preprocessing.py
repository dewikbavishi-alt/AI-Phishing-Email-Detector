import re
import nltk

from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer

# Download resources only if they are missing
for resource, path in [("stopwords", "corpora/stopwords"), ("wordnet", "corpora/wordnet")]:
    try:
        nltk.data.find(path)
    except LookupError:
        nltk.download(resource, quiet=True)

stop_words = set(stopwords.words("english"))
lemmatizer = WordNetLemmatizer()


def preprocess(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\.\S+", " ", text)   # Remove URLs
    text = re.sub(r"[^a-zA-Z]", " ", text)          # Keep only letters
    text = text.split()

    words = []

    for word in text:
        if word not in stop_words and len(word) > 1:
            words.append(lemmatizer.lemmatize(word))

    return " ".join(words)
