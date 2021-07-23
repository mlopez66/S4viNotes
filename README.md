# Hacking notes

This workbook use bookdown Rmarkdown technology. For usage follow [Bookdown original documentation](https://bookdown.org/yihui/bookdown/).

## Dependencies

1. You need to have R installed [R installation guide](https://www.r-project.org/)
1. install **rmarkdown** package

    ```bash
    # Install from CRAN
    install.packages('rmarkdown')

    # Or if you want to test the development version,
    # install from GitHub
    if (!requireNamespace("devtools"))
    install.packages('devtools')
    devtools::install_github('rstudio/rmarkdown')
    ```

1. You need to install **bookdown** package

    ```bash
    # stable version on CRAN
    install.packages("bookdown")
    # or development version on GitHub
    # remotes::install_github('rstudio/bookdown')
    ```

## Local build

### Html output

```bash
Rscript -e "options(bookdown.render.file_scope = FALSE);bookdown::render_book('index.Rmd', 'bookdown::gitbook')"
```

### Pdf output

```bash
RUN Rscript -e "options(bookdown.render.file_scope = FALSE);bookdown::render_book('index.Rmd', 'bookdown::pdf_book')"
```

## docker build

```bash
docker build -t hacking-notes .
docker run -it --rm -p 8080:80 --name hacking-notes hacking-notes
```
