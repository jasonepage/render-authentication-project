import os

PRESET_USERNAMES = [
    "Iron Man", "Black Widow", "Thor", "Spider-Man", "Captain America",
    "Wonder Woman", "Batman", "Superman", "Black Panther", "Doctor Strange",
    "Darth Vader", "Luke Skywalker", "Princess Leia", "Han Solo", "Obi-Wan",
    "Harry Potter", "Hermione", "Ron Weasley", "Dumbledore", "Gandalf",
    "Neo", "Trinity", "Morpheus", "Jack Sparrow", "Indiana Jones",
    "Mario", "Luigi", "Princess Peach", "Link", "Zelda",
    "Sonic", "Pikachu", "Samus", "Master Chief", "Kratos",
    "Leonardo", "Michelangelo", "Raphael", "Donatello", "Yoda"
]

cache = {}

if os.environ.get("FLASK_ENV") == "testing":
    DB_PATH = os.environ.get("TEST_DB_PATH", ":memory:")
else:
    DB_PATH = os.environ.get("DB_PATH", "/opt/render/webauthn.db")
