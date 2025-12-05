;; Qcl mode
(defconst qcl-mode-syntax-table
  (with-syntax-table (copy-syntax-table)
    (modify-syntax-entry ?- ". 124b")
    (modify-syntax-entry ?* ". 23")
    (modify-syntax-entry ?\n "> b")
    (modify-syntax-entry ?' "\"") ; Single quote for character literals
    (modify-syntax-entry ?\" "\"")
    (modify-syntax-entry ?' ".")
    (syntax-table))
  "Syntax table for `qcl-mode'.")

(defun qcl-indent-line ()
  "Indent current line."
  (let (indent
        boi-p
        move-eol-p
        (point (point)))
    (save-excursion
      (back-to-indentation)
      (setq indent (car (syntax-ppss))
            boi-p (= point (point)))
      (when (and (eq (char-after) ?\n)
                 (not boi-p))
        (setq indent 0))
      (when boi-p
        (setq move-eol-p t))
      (when (or (eq (char-after) ?\))
                (eq (char-after) ?\}))
        (setq indent (1- indent)))
      (delete-region (line-beginning-position)
                     (point))
      (indent-to (* tab-width indent)))
    (when move-eol-p
      (move-end-of-line nil))))

(eval-and-compile
  (defconst qcl-types
    '()
    "Type keywords for Qcl mode.")
  (defconst qcl-keywords
    '("if" "else" "true" "false" "null" "$")
    "Non-type keywords for Qcl mode."))

(defconst qcl-highlights
  `((,(concat "\\<" (regexp-opt qcl-types) "\\>")
      . font-lock-type-face)
    (,(concat "\\<" (regexp-opt qcl-keywords) "\\>")
      . font-lock-keyword-face)
    (,(concat "<" (regexp-opt qcl-keywords) ">")
      . font-lock-keyword-face)
    (,(rx (group "\"" (zero-or-more (not (any "\"" "\\"))) (zero-or-one "\\\"") "\""))
      . font-lock-string-face) ; String literals
    (,(rx (group "'" (any "a-zA-Z0-9") "'"))
      . font-lock-string-face) ; Character literals
    (,(rx (group "--" (zero-or-more (not (any "\n"))))
          (group-n 1 (zero-or-more (any "\n"))))
     (1 font-lock-comment-delimiter-face)
     (2 font-lock-comment-face nil t))))

;;;###autoload
(define-derived-mode qcl-mode prog-mode "qcl"
  "Major Mode for editing Qcl source code."
  :syntax-table qcl-mode-syntax-table
  (setq font-lock-defaults '(qcl-highlights))
  (setq-local comment-start "--")
  (setq-local indent-tabs-mode nil)
  (setq-local tab-width 8)
  (setq-local indent-line-function #'qcl-indent-line)
  (setq-local standard-indent 2))

;;;###autoload
(add-to-list 'auto-mode-alist '("\\.qcl\\'" . qcl-mode))

(provide 'qcl-mode)
