"""
Logo AEGIS - affiché au démarrage de l'outil.
"""
from rich.console import Console
from rich.text import Text

console = Console()

COLOR_START = (30, 144, 255)   # bleu électrique
COLOR_MID   = (57, 255, 20)    # vert néon
COLOR_END   = (30, 144, 255)   # retour au bleu


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def _gradient_color(t: float) -> str:
    t = max(0.0, min(1.0, t))
    if t < 0.5:
        t2, c1, c2 = t / 0.5, COLOR_START, COLOR_MID
    else:
        t2, c1, c2 = (t - 0.5) / 0.5, COLOR_MID, COLOR_END
    r = int(_lerp(c1[0], c2[0], t2))
    g = int(_lerp(c1[1], c2[1], t2))
    b = int(_lerp(c1[2], c2[2], t2))
    return f"#{r:02x}{g:02x}{b:02x}"


def _print_gradient(art: str, diagonal: bool = True, bold: bool = True):
    lines = art.rstrip("\n").split("\n")
    width  = max((len(line) for line in lines), default=1)
    height = max(len(lines), 1)

    for y, line in enumerate(lines):
        text = Text()
        for x, ch in enumerate(line):
            if ch == " ":
                text.append(" ")
                continue
            if diagonal:
                t = ((x / max(width - 1, 1)) + (y / max(height - 1, 1))) / 2
            else:
                t = x / max(width - 1, 1)
            style = _gradient_color(t)
            if bold:
                style = f"bold {style}"
            text.append(ch, style=style)
        console.print(text)


SHIELD = r"""                               
   |\             /\             /|
   | \           /  \           / |
   |  \_________/    \_________/  |
   |                              |
   |     ____________________     |
   |    /  ################  \    |
   |   | _______  ##  _______ |   |
   |   |/       | ## |       \|   |
   |            | ## |            |
   |            | ## |            |
   |            | ## |            |
    \           | ## |           /                      
     \          | ## |          /
       \       /______\       /
          \                /
             \          /
                 \  /
"""


def print_logo():
    """Affiche le logo AEGIS complet avec dégradé."""
    try:
        import pyfiglet
        figlet_text = pyfiglet.figlet_format("AEGIS", font="big")
    except ImportError:
        figlet_text = "A E G I S\n"

    console.print()
    _print_gradient(SHIELD, diagonal=True,  bold=True)
    console.print()
    _print_gradient(figlet_text, diagonal=False, bold=True)

    # Tagline sous le logo
    console.print(
        "  [dim]Antivirus à base de signatures · "
        "Python + C++ · "
        "v1.0.0[/dim]\n"
    )


