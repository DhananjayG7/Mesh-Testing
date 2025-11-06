(function () {
  const keyboardEl = document.getElementById("osk");
  if (!window.SimpleKeyboard || !keyboardEl) return;

  let currentInput = null;
  let hideTimer = null;

  // Single layout: numbers + letters + symbols in one board
  const baseLayout = {
    default: [
      "` 1 2 3 4 5 6 7 8 9 0 - = {bksp}",
      "{tab} q w e r t y u i o p [ ] \\",
      "{lock} a s d f g h j k l ; ' {enter}",
      "{shift} z x c v b n m , . / {shift}",
      "{space}"
    ],
    // upper-case variant for Shift/Caps
    shift: [
      "~ ! @ # $ % ^ & * ( ) _ + {bksp}",
      "{tab} Q W E R T Y U I O P { } |",
      "{lock} A S D F G H J K L : \" {enter}",
      "{shift} Z X C V B N M < > ? {shift}",
      "{space}"
    ]
  };

  let isCapsLock = false;

  const keyboard = new window.SimpleKeyboard.default({
    // Attach to #osk explicitly
    keyboardDOM: keyboardEl,
    layout: baseLayout,
    layoutName: "default",
    mergeDisplay: true,
    preventMouseDownDefault: true,
    display: {
      "{bksp}": "⌫",
      "{enter}": "↵",
      "{tab}": "⇥",
      "{lock}": "⇪",
      "{shift}": "⇧",
      "{space}": "⎵"
    },
    onChange: input => {
      if (currentInput) {
        currentInput.value = input;
        currentInput.dispatchEvent(new Event("input", { bubbles: true }));
      }
    },
    onKeyPress: button => handleKey(button)
  });

  function handleKey(button) {
    if (!currentInput) return;

    switch (button) {
      case "{enter}":
        // Optionally submit the form
        currentInput.form && currentInput.form.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));
        // Blur & hide keyboard
        currentInput.blur();
        hideKeyboard(true);
        return;

      case "{tab}":
        focusNextInput(currentInput);
        return;

      case "{shift}":
        toggleShift();
        return;

      case "{lock}":
        toggleCaps();
        return;

      default:
        // Keep caret in sync if user clicked field
        keyboard.setInput(currentInput.value || "");
        return;
    }
  }

  function toggleShift() {
    const current = keyboard.options.layoutName;
    const next = current === "default" ? "shift" : "default";
    // If CapsLock is on, we keep letters uppercase even in "default"
    // but here we'll treat Caps as independent: shift toggles symbols/letters case.
    keyboard.setOptions({ layoutName: next });
  }

  function toggleCaps() {
    isCapsLock = !isCapsLock;
    // CapsLock controls the BASE letters. We emulate by switching layout and
    // remembering caps state: if caps ON and layout is default -> show shift letters,
    // if caps ON and layout is shift -> keep shift (caps + shift behaves like default letters upper).
    const layoutName = keyboard.options.layoutName;
    if (isCapsLock && layoutName === "default") {
      keyboard.setOptions({ layoutName: "shift" });
    } else if (!isCapsLock && layoutName === "shift") {
      keyboard.setOptions({ layoutName: "default" });
    }
  }

  function showKeyboardFor(el) {
    currentInput = el;
    keyboard.setInput(el.value || "");
    keyboardEl.style.display = "block";
    keyboardEl.style.zIndex = 9999;
    document.body.classList.add("osk-open"); // adds bottom padding equal to keyboard height
    clearTimeout(hideTimer);
  }

  function hideKeyboard(force = false) {
    clearTimeout(hideTimer);
    const doHide = () => {
      currentInput = null;
      keyboardEl.style.display = "none";
      keyboard.clearInput();
      document.body.classList.remove("osk-open"); // remove extra padding
    };
    if (force) return doHide();
    hideTimer = setTimeout(doHide, 80);
  }

  function isTextInput(el) {
    if (!el) return false;
    const t = (el.type || "").toLowerCase();
    return (
      (el.tagName === "INPUT" && ["text","search","email","password","number","tel","url"].includes(t)) ||
      el.tagName === "TEXTAREA"
    );
  }

  // Keep open when clicking inside keyboard
  keyboardEl.addEventListener("mousedown", e => { clearTimeout(hideTimer); e.preventDefault(); });

  // Auto show/hide on focus
  document.addEventListener("focusin", e => {
    if (isTextInput(e.target)) showKeyboardFor(e.target);
  });
  document.addEventListener("focusout", e => {
    const to = e.relatedTarget;
    if (isTextInput(to)) return;
    if (keyboardEl.contains(to)) return;
    hideKeyboard(false);
  });

  // Keep text mirrored if user clicks back into a field
  document.addEventListener("click", e => {
    if (isTextInput(e.target)) keyboard.setInput(e.target.value || "");
  });

  function focusNextInput(el) {
    const inputs = Array.from(document.querySelectorAll("input, textarea"))
      .filter(isTextInput)
      .filter(i => !i.disabled && i.offsetParent !== null);
    const idx = inputs.indexOf(el);
    if (idx >= 0 && idx < inputs.length - 1) inputs[idx + 1].focus();
  }
})();
