import board
import neopixel

# CONFIGURATION
NUM_LEDS = 4
PIXEL_PIN = board.D13
ORDER = neopixel.GRB
BRIGHTNESS = 0.9

strip = neopixel.NeoPixel(
    PIXEL_PIN,
    NUM_LEDS,
    brightness=BRIGHTNESS,
    auto_write=True,
    pixel_order=ORDER
)

class LEDController:
    def __init__(self):
        self.white()

    def set_all(self, rgb):
        strip.fill(rgb)
        strip.show()

    def green(self):
        self.set_all((0, 255, 0))

    def red(self):
        self.set_all((255, 0, 0))

    def white(self):
        self.set_all((255, 255, 255))

    def off(self):
        self.set_all((0, 0, 0))

led_controller = LEDController()
