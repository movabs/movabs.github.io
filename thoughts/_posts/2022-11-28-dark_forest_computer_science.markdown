---
layout: default
title:  "Dark forest - What am I even doing?"
date:   2022-11-28 21:17:30 +0100
category: thoughts
---

# (Dark forest) - what am I even doing?

I'm often asked "what I'm doing". Many have certain misunderstanding and stereotypes that make the simple answer of
"Computer Science" insufficient.

This is an attempt to answer this simple question, in the hopes that I can simple refer people to this article 
instead of explain this for the thousandth time.

## What am I doing?

Simply put "Computer Science". Then what "Computer Science" is? It is all about solving problems.
It then makes a new question (As in ROP-Chain), what is problems? In this context, a problem is a language. You read it right.
A language just like "English", "French" or "Arabic".

### So languages are problems?

A language consists of a set of grammar rules and a set of words that constitute a vocabulary. For example, this article
is a part of the English language because all the sentences conform to the English grammar, and all the words of
the sentences are of the English vocabulary. Though sentences like "He coding", or "He code written" don't conform with
the English grammar, the first one lacks of a verb and the second one is unclear from the word order which noun is the
subject and which is the object.

Turns out that a lot of read-world problems and virtually all computational problems can be represented in terms of languages.
For example, if we want to check if a list of numbers is sorted in order. The problem is same as creating a language in which
the vocabulary is the set of all the numbers, the grammar only allows non-decreasing numbers to appear one after another,
and the problem then becomes testing if the given list is a member of that language?

That being said, "Computer Scientists" work is often concerned with "automatically" and "efficiently" testing if a given
sentence conforms to a given language.

### Skyscrapers

Let's take Skyscrapers as an example. A "language" for Skyscrapers might consist of:
- Vocabulary: 1, 2, 3, 4, 5
- Grammar: The set of all sentences that are exactly 5 * 5 = 25 characters long (25 squares) and that conform the 
  Skyscrapers property (Of course that could be different).

It's relatively easy to check if a sentence conforms to the Skyscrapers grammar by a human, however, here we're interested
in a computer scientist's point of view. A computer science might try "Given a partially complete sentence, either complete
the sentence such that it conforms to the Skyscrapers grammar or prove that such a completion does not exist."
This is much harder to solve.

As we said `"Computer Scientists" work is often concerned with "automatically" and "efficiently"`. Now about "efficiently",
let's see how an algorithm could be expensive. Testing if a sentence conforms to the grammar is an easy task, one could
enumerate all the possible grid layouts and find the first possible solution that is part of the grammar. The problem is
that, in the worst case, there will be 5<sup>25</sup> = 298023223876953125 possibilities!

See? How "efficiently" matters?

## So what Computer Science is?

One way of thinking about "Computer Scientists" is in what type of problems they aim to solve.
There are problems that are so complex that either no approximation can be found or, perhaps, the grammar isn't even known
for the problem's language. Foe example, consider poker. Since it's both non-deterministic and unobservable, an optimal
poker-playing algorithm will be a function of the other players strategies. Creating an algorithm may require building 
[heuristics](https://en.wikipedia.org/wiki/Heuristic).
The last example generally falls under the term "Artificial Intelligence (AI)". The creation of algorithms capable of 
finding solutions to arbitrarily difficult problems, And there are generally two camps: "neats" and rge "scruffies".
The "neats" like to design systems using formal logic and mathematics, since such methods are infallible, ince a method
is produced then the work is done. The "scruffies", on the other hand, like to engineer systems that tend to get the job done
and then, retrospectively, examine the system and figure out why it worked.

**And that is what I'm probably going to be doing for the next six months, under the "scruffies" camp.**
