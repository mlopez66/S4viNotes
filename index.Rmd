--- 
title: 2021 - S4viNotes
author: Lo0pInG 404
resume: |
  `r paste(readLines("00-Preface/00_Resume.Rmd"), collapse = '\n  ')`
date: updated on `r Sys.Date()`
description: Full Pentest notebook
documentclass: book
github-repo: https://github.com/mlopez66/hacking-notes
always_allow_html: yes
bibliography: bibliography.bib
biblio-style: apalike
link-citations: yes
---

```{r setup, include=F, warning=F, message=F}
knitr::opts_chunk$set(echo = F)
```

```{r child="00-Preface/00_Resume.Rmd", include=identical(knitr:::pandoc_to(), 'html')}
```
