;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Start of xbindkeys configuration ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; This configuration is guile based.
; any functions that work in guile will work here.
; see EXTRA FUNCTIONS:

; Version: 1.7.1

; If you edit this file, do not forget to uncomment any lines
; that you change.
; The semicolon(;) symbol may be used anywhere for comments.

; To specify a key, you can use 'xbindkeys --key' or
; 'xbindkeys --multikey' and put one of the two lines in this file.

; A list of keys is in /usr/include/X11/keysym.h and in
; /usr/include/X11/keysymdef.h
; The XK_ is not needed.

; List of modifier:
;   Release, Control, Shift, Mod1 (Alt), Mod2 (NumLock),
;   Mod3 (CapsLock), Mod4, Mod5 (Scroll).


; The release modifier is not a standard X modifier, but you can
; use it if you want to catch release instead of press events

; By defaults, xbindkeys does not pay attention to modifiers
; NumLock, CapsLock and ScrollLock.
; Uncomment the lines below if you want to use them.
; To dissable them, call the functions with #f


;EXTRA FUNCTIONS:
;(set-numlock! #t)
;(set-scrolllock! #t)
;(set-capslock! #t)
;(xbindkey key "foo-bar-command [args]")
;(xbindkey '(modifier* key) "foo-bar-command [args]")
;that is, xbindkey can take a list of modifiers ended by a key
;                  or it can just take a plain key.

; Examples of commands:

;(xbindkey '(control q) "xbindkeys_show")

; set directly keycode (here control + f with my keyboard)
;(xbindkey '("m:0x4" "c:41") "xterm")

; specify a mouse button
(xbindkey '(release "b:7") "xvkbd -xsendevent -no-jump-pointer -text '\\[Home]'")
(xbindkey '(release "b:6") "xvkbd -xsendevent -no-jump-pointer -text '\\[End]'")

;; logitech
;(xbindkey '(release "b:6") "xvkbd -no-jump-pointer -text '\\[Home]'")
;(xbindkey '(release "b:7") "xvkbd -no-jump-pointer -text '\\[End]'")
;(xbindkey '(release "b:9") "xvkbd -no-jump-pointer -text '\\[Next]'")
;; labtec
;(xbindkey '(release "b:10") "xvkbd -no-jump-pointer -text '\\[Home]'")
;(xbindkey '(release "b:11") "xvkbd -no-jump-pointer -text '\\[End]'")
;(xbindkey '(release "b:7") "xvkbd -xsendevent -no-jump-pointer -text '\\[Home]'")
;(xbindkey '(release "b:6") "xvkbd -xsendevent -no-jump-pointer -text '\\[End]'")

;(xbindkey '(shift mod2 alt s) "xterm -geom 50x20+20+20")

;; set directly keycode (control+alt+mod2 + f with my keyboard)
;(xbindkey '(alt "m:4" mod2 "c:0x29") "xterm")

; Control+Shift+a  release event starts rxvt
;(xbindkey '(release control a) "xterm")

; Control + mouse button 2 release event starts rxvt
;(xbindkey '(release control "b:2") "rxvt")

