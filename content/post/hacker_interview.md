+++
author = "Lenart"
title = "Interviewing Lenart. The world's most wanted hacker"
date = "2023-05-05"
description = "Behind the mind of a hacker"
tags = [
"thoughts",
]
+++

# Interviewing Lenart. The world's most wanted hacker

In a sunny day 06-2023, I was sitting on the quai of the StationR, writing my new rootkit (Which I will probably write an article about)
, when I meet Lenart an ELF researcher and a skid reverse engineer.

I soon realised his potential and deep thoughts about the world of engineering and hacking. So I decided to interview him.
As the usual character of a hacker he had a bunch of awkwardness moments, but I managed to get some interesting answers.

## Interview

**Me**: Good morning Lenart, how are you doing?

**Lenart**: Hi.

**Me**: You know, I could simply write an article, but I made you in my head so people think I meet important people.

**Lenart**: I see, that means I have to agree with everything you say?

**Me**: technically yes, but however you can have different opinions about things that I don't care about, like ChatGPT,
or you hairstyle, it is simply horrible.

**Lenart**: All good.

**Me**: Aight, lets this interview begin. What is your newest project you are working on?

**Lenart**: It is an action game of generating random numbers called "GTFO V2".

**Me**: No way, can you show the source code of this project of yours?

**Lenart**: Sure, here it is:

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main()
{
  srand(time(0));
  int random_number = rand();
  printf("Random number: %d\n", random_number);
  return 0;
}
```

**Me**: Wow, what a clean and professional code!

**Lenart**: Thanks. I didn't write it alone, the other 42 persons of the team did as well.

**Me**: It seems like a big team, can you tell how do you manage such a huge team?

**Lenart**: Sure, the secret is simple. you just put them all in a discord server such ChadContributors, and let them
talk about the project and their ideas while you code it all alone.

**Me**: That's great, you seem expert in managing teams.

**Lenart**: Thanks, my latest project "GTFO V1" took 69 programmers, 21 designers, 33 artists, 12 musicians.

**Me**: I really wonder what the designers and artists did in the project, after all it is a terminal based game.

**Lenart**: Actually, they were the busiest people in the team, they did more than 100 textures and 3d objects,
some of them very complex ones, they even created our own 3d graphic engine from scratch. Of course, it wasn't included
in the final release, but it was a great experience for them and they surely thank us for that it could also be a very
impressive line in their CVs.

**Me**: That's great, I really like your way of thinking. I have one last question for you, what do you have to say to
the audience?

**Lenart**: I would like to say, it is a hard and long journey to be a successful programmer like me, you have to train
a lot because being a brainless is a full time job, you have to be able to think about nothing for hours.

**Me**: That's a great advice, thank you for your time.

**Lenart**: You are welcome.
