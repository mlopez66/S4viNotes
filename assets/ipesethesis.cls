%
% This file is copyright (C) 2003 Sam Noble. It may be modified so long
% as my name is not removed and the modifier adds his name to the file.
% Redistribution permitted.
%
% 27 Jan 2004	Sam Noble	Removed tocbibind dependency.
% 04 Dec 2001 	Sam Noble	Class file
% 03 Sep 1995	David Perkinson	Title Page
% Acknowledgements Page, David Perkinson & Sam Noble
% May 2005 Patrick Carlisle Table of contents chapter definition
% 2004-2005 Ben Salzberg (BTS) a variety of tweaks here and in the template
% 2015 Chester Ismay (CII) modified to create R Markdown template
%
% Oddities:
%
%   We *ASSUME* that any time \cleardoublepage is called
%  we actually want a blank back side with NO page number/heading
%
%   Minor bug -- seems to be a more general LaTeX thing:
%  If you use \frontmatter \mainmatter without any chapters inbetween
%  be prepared to have the page numbering messed up. Not a big deal,
%  but I'm not sure how to fix it.
%
%

\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{assets/assetsthesis}[2019/06/19 assets Thesis Class]
\DeclareOption*{\PassOptionsToClass{\CurrentOption}{book}}
\ProcessOptions\relax
\LoadClass[11pt,a4paper,oneside]{book}
\RequirePackage{fancyhdr}
% Added by CII to produce nice looking code in BeginVerbatimEnvironment
\RequirePackage{fancyvrb}
\RequirePackage{graphicx}

% Added by CII
\usepackage{ifxetex,ifluatex}
\usepackage{fixltx2e} % provides \textsubscript
\ifnum 0\ifxetex 1\fi\ifluatex 1\fi=0 % if pdftex
  \usepackage[T1]{fontenc}
  \usepackage[utf8]{inputenc}
\else % if luatex or xelatex
  \ifxetex
    \usepackage{mathspec}
    \usepackage{xltxtra,xunicode}
  \else
    \usepackage{fontspec}
  \fi
  \defaultfontfeatures{Mapping=tex-text,Scale=MatchLowercase}
  \newcommand{\euro}{€}
\fi
% use upquote if available, for straight quotes in verbatim environments
\IfFileExists{upquote.sty}{\usepackage{upquote}}{}
% use microtype if available
\IfFileExists{microtype.sty}{%
\usepackage{microtype}
\UseMicrotypeSet[protrusion]{basicmath} % disable protrusion for tt fonts
}{}
\usepackage{color}
%\newcommand{\VerbBar}{|}
%\newcommand{\VERB}{\Verb[commandchars=\\\{\}]}
\DefineVerbatimEnvironment{verbatim}{Verbatim}{xleftmargin=-1em}
\DefineVerbatimEnvironment{Highlighting}{Verbatim}{commandchars=\\\{\}}
% Add ',fontsize=\small' for more characters per line
\usepackage{framed}
\definecolor{shadecolor}{RGB}{248,248,248}
% \newenvironment{Shaded}{\begin{snugshade}}{\end{snugshade}}
% \newcommand{\KeywordTok}[1]{\textcolor[rgb]{0.13,0.29,0.53}{\textbf{{#1}}}}
% \newcommand{\DataTypeTok}[1]{\textcolor[rgb]{0.13,0.29,0.53}{{#1}}}
% \newcommand{\DecValTok}[1]{\textcolor[rgb]{0.00,0.00,0.81}{{#1}}}
% \newcommand{\BaseNTok}[1]{\textcolor[rgb]{0.00,0.00,0.81}{{#1}}}
% \newcommand{\FloatTok}[1]{\textcolor[rgb]{0.00,0.00,0.81}{{#1}}}
% \newcommand{\ConstantTok}[1]{\textcolor[rgb]{0.00,0.00,0.00}{{#1}}}
% \newcommand{\CharTok}[1]{\textcolor[rgb]{0.31,0.60,0.02}{{#1}}}
% \newcommand{\SpecialCharTok}[1]{\textcolor[rgb]{0.00,0.00,0.00}{{#1}}}
% \newcommand{\StringTok}[1]{\textcolor[rgb]{0.31,0.60,0.02}{{#1}}}
% \newcommand{\VerbatimStringTok}[1]{\textcolor[rgb]{0.31,0.60,0.02}{{#1}}}
% \newcommand{\SpecialStringTok}[1]{\textcolor[rgb]{0.31,0.60,0.02}{{#1}}}
% \newcommand{\ImportTok}[1]{{#1}}
% \newcommand{\CommentTok}[1]{\textcolor[rgb]{0.56,0.35,0.01}{\textit{{#1}}}}
% \newcommand{\DocumentationTok}[1]{\textcolor[rgb]{0.56,0.35,0.01}{\textbf{\textit{{#1}}}}}
% \newcommand{\AnnotationTok}[1]{\textcolor[rgb]{0.56,0.35,0.01}{\textbf{\textit{{#1}}}}}
% \newcommand{\CommentVarTok}[1]{\textcolor[rgb]{0.56,0.35,0.01}{\textbf{\textit{{#1}}}}}
% \newcommand{\OtherTok}[1]{\textcolor[rgb]{0.56,0.35,0.01}{{#1}}}
% \newcommand{\FunctionTok}[1]{\textcolor[rgb]{0.00,0.00,0.00}{{#1}}}
% \newcommand{\VariableTok}[1]{\textcolor[rgb]{0.00,0.00,0.00}{{#1}}}
% \newcommand{\ControlFlowTok}[1]{\textcolor[rgb]{0.13,0.29,0.53}{\textbf{{#1}}}}
% \newcommand{\OperatorTok}[1]{\textcolor[rgb]{0.81,0.36,0.00}{\textbf{{#1}}}}
% \newcommand{\BuiltInTok}[1]{{#1}}
% \newcommand{\ExtensionTok}[1]{{#1}}
% \newcommand{\PreprocessorTok}[1]{\textcolor[rgb]{0.56,0.35,0.01}{\textit{{#1}}}}
% \newcommand{\AttributeTok}[1]{\textcolor[rgb]{0.77,0.63,0.00}{{#1}}}
% \newcommand{\RegionMarkerTok}[1]{{#1}}
% \newcommand{\InformationTok}[1]{\textcolor[rgb]{0.56,0.35,0.01}{\textbf{\textit{{#1}}}}}
% \newcommand{\WarningTok}[1]{\textcolor[rgb]{0.56,0.35,0.01}{\textbf{\textit{{#1}}}}}
% \newcommand{\AlertTok}[1]{\textcolor[rgb]{0.94,0.16,0.16}{{#1}}}
% \newcommand{\ErrorTok}[1]{\textcolor[rgb]{0.64,0.00,0.00}{\textbf{{#1}}}}
% \newcommand{\NormalTok}[1]{{#1}}

\setlength{\emergencystretch}{3em}  % prevent overfull lines
\providecommand{\tightlist}{%
  \setlength{\itemsep}{0pt}\setlength{\parskip}{0pt}}
% End of CII add

% This gives us rules below the headers
\AtBeginDocument{%
%  \fancyhf{}
%  \fancyhead[LE,RO]{\thepage}
%%  \fancyhead[RE]{\slshape \leftmark}
%%  \fancyhead[LO]{\slshape \rightmark}
%%	The above makes your headers in all caps. If you would like different headers, choose one of the following options (be sure to remove the % symbol from both the right and left headers):
%	 \fancyhead[RE]{\slshape \nouppercase \leftmark} % This makes the headers on the RIGHT side pages be italic and use lowercase With Capitals When Specified.
%	\fancyhead[LO]{\slshape \nouppercase \rightmark} % This does the same thing to the LEFT side pages
%%	or
%%	\fancyhead[RE]{\scshape \leftmark} % The RIGHT headers will be in small caps.
%%	\fancyhead[LO]{\scshape \rightmark} %  And so will the LEFT headers
%  \pagestyle{fancy}
    %///////////////////////////////////////////////////////////////////////////////////////////////////////
    % header and footer
%    \usepackage{fancyhdr}
    \pagestyle{fancy}
    \renewcommand{\chaptermark}[1]{\markboth{\small{\textsc{#1}}}{}}
    \renewcommand{\sectionmark}[1]{\markright{\small{\thesection}\ \textsc{#1}}}
    \renewcommand{\headrulewidth}{1pt}
    \renewcommand{\footrulewidth}{1pt}
    \fancyhf{}
    %\fancyhead[CE]{\textsc{\nouppercase{\leftmark}}}
    \fancyhead[CO]{\textsc{\nouppercase{\rightmark}}}
    \fancyfoot[C]{\thepage}
    \renewcommand{\headrule}{\hbox to\headwidth{%
        \color{teal}\leaders\hrule height \headrulewidth\hfill}}
    \renewcommand{\footrule}{\hbox to\headwidth{%
        \color{white}\leaders\hrule height \footrulewidth\hfill}}
    \fancypagestyle{mine}{
      \fancyhead{}
      \renewcommand{\headrulewidth}{0.1pt}
      \renewcommand{\footrulewidth}{0.0pt}}

% Psych majors: You do not need the following six lines, as it conflicts with apacite, so comment them out.
  \let\oldthebibliography=\thebibliography
  \let\endoldthebibliography=\endthebibliography
  \renewenvironment{thebibliography}[1]{
    \oldthebibliography{#1}
    \addcontentsline{toc}{chapter}{\bibname}
  }{\endoldthebibliography}
 %%%%%% end of things for psych majors to comment out

  \let\oldtheindex=\theindex
  \let\endoldtheindex=\endtheindex
  \renewenvironment{theindex}{
    \oldtheindex
    \addcontentsline{toc}{chapter}{\indexname}
  }{\endoldtheindex}
}

% Stolen from book.cls and modified
\let\RToldchapter\chapter
\renewcommand{\chapter}{
            \if@openright\RTcleardoublepage
		    \else\clearpage\fi
		    \thispagestyle{empty}%
		    \global\@topnum\z@
		    \@afterindentfalse
		    \secdef\@chapter\@schapter}

% Stolen from book.cls PBC 5/12/05
% Using this to actually show "Chapter 1" in TOC instead of "1"
\def\@chapter[#1]#2{\ifnum \c@secnumdepth >\m@ne
                       \if@mainmatter
                         \refstepcounter{chapter}%
                         \typeout{\@chapapp\space\thechapter.}%
                         \addcontentsline{toc}{chapter}%
                         {\@chapapp\space\thechapter:\space#1}%
                       \else
                         \addcontentsline{toc}{chapter}{#1}%
                       \fi
                    \else
                      \addcontentsline{toc}{chapter}{#1}%
                    \fi
                    \chaptermark{#1}%
                    \addtocontents{lof}{\protect\addvspace{10\p@}}%
                    \addtocontents{lot}{\protect\addvspace{10\p@}}%
                    \if@twocolumn
                      \@topnewpage[\@makechapterhead{#2}]%
                    \else
                      \@makechapterhead{#2}%
                      \@afterheading
                    \fi}

\newcommand{\RTcleardoublepage}{
	\clearpage\if@twoside \ifodd\c@page\else
	\thispagestyle{empty}\hbox{}\newpage
	\if@twocolumn\hbox{}\newpage\fi\fi\fi}

\let\RToldcleardoublepage\cleardoublepage
\renewcommand{\cleardoublepage}{\RTcleardoublepage}

% adjust margins for binding  (changed 2007-04-24 tgp)
\setlength{\oddsidemargin}{.5in}
\setlength{\evensidemargin}{0in}
\setlength{\textwidth}{6.0in}
\setlength{\textheight}{9.0in}
\setlength\topmargin{0in}
\addtolength\topmargin{-\headheight}
\addtolength\topmargin{-\headsep}

%\setlength{\oddsidemargin}{.6in}
%\setlength{\evensidemargin}{0in}
%\setlength{\textwidth}{5.9in}
%\setlength\topmargin{0in}
%\addtolength\headheight{2.5pt}
%\addtolength\topmargin{-\headheight}
%\addtolength\topmargin{-\headsep}
%\addtolength\textheight{1in}
%\addtolength\textheight{\headheight}
%\addtolength\textheight{\headsep}

\def\scholardegree#1{\gdef \@scholardegree{#1}}
\def\@scholardegree{\@latex@warning@no@line{No \noexpand\scholardegree given}}
\def\institution#1{\gdef \@institution{#1}}
\def\@institution{\@latex@warning@no@line{No \noexpand\institution given}}
\def\division#1{\gdef \@division{#1}}
\def\@division{\@latex@warning@no@line{No \noexpand\division given}}
\def\department#1{\gdef \@department{#1}}
\def\@department{\@latex@warning@no@line{No \noexpand\department given}}
\def\thedivisionof#1{\gdef \@thedivisionof{#1}}
\def\@thedivisionof{The Division of}
\def\approvedforthe#1{\gdef \@approvedforthe{#1}}
\def\@approvedforthe{Division}
\def\advisor#1{\gdef \@advisor{#1}}
\def\@advisor{\@latex@warning@no@line{No \noexpand\advisor given}}
\def\altadvisor#1{\gdef \@altadvisor{#1} \@altadvisortrue}
\global\let\@altadvisor\@empty
\newif\if@altadvisor
\@altadvisorfalse

\renewcommand\l@chapter[2]{%
  \ifnum \c@tocdepth >\m@ne
    \addpenalty{-\@highpenalty}%
    \vskip 1.0em \@plus\p@
    \setlength\@tempdima{1.5em}%
    \begingroup
      \parindent \z@ \rightskip \@pnumwidth
      \parfillskip -\@pnumwidth
      \leavevmode \bfseries
      \advance\leftskip\@tempdima
      \hskip -\leftskip
      #1\nobreak\normalfont
      \leaders\hbox{$\m@th \mkern \@dotsep mu\hbox{.}\mkern \@dotsep mu$}\hfill
      \nobreak\hb@xt@\@pnumwidth{\bfseries \hss #2}\par
      \penalty\@highpenalty
    \endgroup
  \fi}

%%% Added by CII
\newenvironment{acknowledgements}{%
  \if@twocolumn
    \@restonecoltrue\onecolumn
  \else
    \@restonecolfalse
  \fi
  \chapter*{Acknowledgements}
  \fontsize{12}{14}\selectfont
}{\clearpage \if@restonecol\twocolumn\fi}%

\newenvironment{preface}{%
  \if@twocolumn
    \@restonecoltrue\onecolumn
  \else
    \@restonecolfalse
  \fi
  \chapter*{Preface}
  \fontsize{12}{14}\selectfont
}{\clearpage \if@restonecol\twocolumn\fi}%
% End of CII add

\newenvironment{abstract}{%
  \if@twocolumn
    \@restonecoltrue\onecolumn
  \else
    \@restonecolfalse
  \fi
  \chapter*{Abstract}
  \fontsize{12}{14}\selectfont
}{\clearpage \if@restonecol\twocolumn\fi}%

\newenvironment{resume}{%
  \if@twocolumn
    \@restonecoltrue\onecolumn
  \else
    \@restonecolfalse
  \fi
  \chapter*{Résumé}
  \fontsize{12}{14}\selectfont
}{\clearpage \if@restonecol\twocolumn\fi}%

\newenvironment{dedication}{%
  \if@twocolumn
    \@restonecoltrue\onecolumn
  \else
    \@restonecolfalse
  \fi
  \chapter*{Dedication}
  \fontsize{12}{14}\selectfont
}{\clearpage \if@restonecol\twocolumn\fi}%


\ifx\@pdfoutput\@undefined
  \newcommand{\RTpercent}{\@percentchar\space}
  \AtBeginDvi{\special{!\RTpercent Reed College LaTeX Thesis Class 2001/12/04 SN}}
  \AtBeginDvi{\special{rawpostscript \RTpercent Reed College LaTeX Thesis Class 2001/12/04 SN}}
\else
  \AtEndDocument{\pdfinfo{/Creator	(Reed College LaTeX Thesis Class 2001/12/04 SN)}}
\fi

\renewcommand{\maketitle}{%
  {
  \begin{titlepage}
      \thispagestyle{EPFLletterfirst}
      \begin{center}
        \noindent \LARGE \textbf{\MakeUppercase{\@scholardegree}} \\
        \vfill
        \vspace*{0.8cm}
        \noindent {\bfseries\Huge \@title\par}
        \vspace*{0.8cm}
        \noindent \large {by\\}
        \vspace*{0.1cm}
        \noindent \LARGE \@author \\
        \vfill
        \vspace*{0.2cm}
        \noindent \large \@date \\
        \vspace*{0.5cm}
        %\large \textbf{Jury} \\
        \noindent \large
        \begin{tabular}{ll}
              \textit{Professor}:       & \@advisor \\
              %\textit{Supervisors}:     & Xiang Li \\
              %                          & Dr. Theodoros  Damartzis \\
        \end{tabular}
    \end{center}
  \end{titlepage}
  }
}

% From JSS
% Added by CII
\renewcommand{\title}[1]{\def\@title{#1}}
%\newcommand{\Shorttitle}[1]{\def\@Shorttitle{#1}}
\newcommand{\Plainauthor}[1]{\def\@Plainauthor{#1}}
\newcommand{\Abstract}[1]{\def\@Abstract{#1}}
%\newcommand{\Keywords}[1]{\def\@Keywords{#1}}
%\newcommand{\Plainkeywords}[1]{\def\@Plainkeywords{#1}}
\newcommand{\Acknowledgements}[1]{\def\@Acknowledgements{#1}}
\newcommand{\Dedication}[1]{\def\@Dedication{#1}}
\newcommand{\Preface}[1]{\def\@Preface{#1}}
% End of CII add


%///////////////////////////////////////////////////////////////////////////////////////////////////////
%///////////////////////////////////////////////////////////////////////////////////////////////////////
%///////////////////////////////////////////////////////////////////////////////////////////////////////
% class file for my phd thesis
% richard
% september 2008
% Modified by Maziar Kermani November 11, 2017
%///////////////////////////////////////////////////////////////////////////////////////////////////////
%///////////////////////////////////////////////////////////////////////////////////////////////////////
%///////////////////////////////////////////////////////////////////////////////////////////////////////
\ProcessOptions
%///////////////////////////////////////////////////////////////////////////////////////////////////////
% EPFL tempelate margins
\setlength{\textwidth}{146.8mm} 	% = 210mm - 37mm - 26.2mm. (Original)
\setlength{\oddsidemargin}{11.6mm} 	% = 37mm - 1in (from hoffset) (Original)
\setlength{\evensidemargin}{0.8mm} 	% = 26.2mm - 1in (from hoffset)  (Original)
% Kermani (adapted from Moret): reduced right and left margin by a total of 9mm: 37mm -> 32mm, 26.2mm -> 22.2mm
\setlength{\hoffset}{-3.4mm} 		% 22mm - 1in. 1in is the default value (Modified)
\setlength{\textwidth}{155.8mm} 	% = 210mm - 32mm - 21.8mm. (Modified)
\setlength{\oddsidemargin}{10mm}  	% = 32mm - 22mm (from hoffset) (Modified)
\setlength{\evensidemargin}{0.2mm} % = 22.2mm - 22mm (from hoffset)
\setlength{\topmargin}{-2.2mm} 		% = 0mm -1in + 23.2mm
\setlength{\textheight}{221.9mm} 	% = 297mm -29.5mm -31.6mm - 10mm (12 to accomodate footline with pagenumber)
%\setlength{\headheight}{14pt}
\setlength{\headheight}{23.3pt}

%///////////////////////////////////////////////////////////////////////////////////////////////////////
% typeface
\usepackage[T1]{fontenc}
\usepackage[utf8]{inputenc}

%%\usepackage[osf]{mathpazo} % Palatino with smallcaps and oldstyle numbers very bold
%%\usepackage{mathpazo}     % not good
%%\usepackage{pslatex}      % not good
%%\usepackage{mathptmx}     % not good
%\usepackage[scaled]{helvet} % Helvetica, scaled 95%
%\usepackage{lmodern}
%\usepackage{aecompl} % similar to eco
\usepackage{eco}
\usepackage{calligra}
%///////////////////////////////////////////////////////////////////////////////////////////////////////
% colors
\usepackage{color}
\usepackage[many]{tcolorbox}
%///////////////////////////////////////////////////////////////////////////////////////////////////////
% color definitions
\definecolor{myblue}{RGB}{70,181,211}
\definecolor{teal}{RGB}{0,128,128}
\definecolor{darkteal}{RGB}{0,102,102}
%\definecolor{teal}{RGB}{0,0,206} % blue
\definecolor{teallight}{RGB}{102,178,178}
\definecolor{tealblue}{RGB}{54, 117, 136}
\definecolor{titlebgdark}{RGB}{0,163,243}
\definecolor{titlebglight}{RGB}{191,233,251}
\definecolor{verylightgray}{RGB}{231,231,231}
\definecolor{dimgray}{RGB}{105,105,105}
\definecolor{mediumblue}{RGB}{0,0,205}
\definecolor{cornflowerblue}{RGB}{100,149,237}
\definecolor{royalblue}{RGB}{65,105,225}
%///////////////////////////////////////////////////////////////////////////////////////////////////////
% chapter title style
\usepackage{fncychap}
\makeatletter
    \ChNameVar{\Large\scshape}
    \ChNumVar{\Huge}
    \ChTitleVar{\Huge\normalfont\bfseries}
\makeatother
%///////////////////////////////////////////////////////////////////////////////////////////////////////
% blank left/even page at the end of the chapter
\makeatletter
  \def\cleardoublepage{\clearpage\if@twoside
  \ifodd\c@page
  \else\hbox{}\thispagestyle{empty}\newpage
  \if@twocolumn\hbox{}\newpage\fi\fi\fi}
\makeatother
%///////////////////////////////////////////////////////////////////////////////////////////////////////
% nomenclature
\usepackage{ifthen}
%\usepackage[refpage,intoc]{nomencl}
\usepackage[intoc]{nomencl}
\makenomenclature
\renewcommand{\nomname}{Nomenclature}
%\renewcommand{\eqdeclaration}[1]{, (#1)}
%\renewcommand{\pagedeclaration}[1]{, #1}
\renewcommand{\nomgroup}[1]{%
  \ifthenelse{\equal{#1}{A}}{\item[\textbf{Abbreviations}]}{%	Abbreviations
  \ifthenelse{\equal{#1}{R}}{\item[\textbf{Roman letters}]}{%	Roman letters
  \ifthenelse{\equal{#1}{G}}{\item[\textbf{Greek letters}]}{%	Greek letters
  \ifthenelse{\equal{#1}{S}}{\item[\textbf{Subscripts}]}{%
  \ifthenelse{\equal{#1}{T}}{\item[\textbf{Superscripts}]}}}}}}
\newcommand{\nomunit}[1]{%
  \renewcommand{\nomentryend}{\hspace*{\fill}#1}}%
%///////////////////////////////////////////////////////////////////////////////////////////////////////
% acronyms
% handle acronyms but don't make a list, use nomenclature
\usepackage[printonlyused,nolist]{acronym}
\newcommand{\acname}{Acronyms \& abbreviations}
\usepackage[acronym]{glossaries}
\glsenablehyper
%///////////////////////////////////////////////////////////////////////////////////////////////////////
% index
\usepackage{makeidx}
\makeindex
\newcommand{\idxname}{Index}
%///////////////////////////////////////////////////////////////////////////////////////////////////////
% epigraphs
\usepackage{epigraph}
\newcommand{\myepigraph}[2]{\epigraph{\emph{#1}}{#2}}
%///////////////////////////////////////////////////////////////////////////////////////////////////////
\endinput
