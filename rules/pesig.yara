rule PeSig {
  strings:
    $dosText = "This program cannot be run in DOS mode"
    $PeMagic = { 45 50 00 00 }
    $TextSec = ".text"
    $CodeSec = ".code"
  condition:
    ($dosText and ($TextSec or $CodeSec)) or ($PeMagic and ($TextSec or $CodeSec))
 }
 