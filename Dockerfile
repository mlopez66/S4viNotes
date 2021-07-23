FROM looping404/bookdown:1.0.0 as build
copy . /app
WORKDIR /app
RUN Rscript -e "options(bookdown.render.file_scope = FALSE);bookdown::render_book('index.Rmd', 'bookdown::gitbook')"
RUN Rscript -e "options(bookdown.render.file_scope = FALSE);bookdown::render_book('index.Rmd', 'bookdown::pdf_book')"
copy assets/7th-Service-Condensed.ttf.woff2 _book/assets
copy assets/7th-Service-Condensed.ttf.woff _book/assets

FROM nginx:latest
WORKDIR /usr/share/nginx/html
COPY --from=build /app/_book .
