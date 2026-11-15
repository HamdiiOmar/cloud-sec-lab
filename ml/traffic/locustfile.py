"""Phase 5: normal-traffic generator for Juice Shop (the "benign" class for the ML models).

Runs on the host (192.168.56.1), so everything from that IP is labeled normal.
Each simulated user registers, logs in, then browses like a shopper with think time between actions.
"""
import random
import string
import time

from locust import HttpUser, between, task

SEARCH_TERMS = [
    "apple", "orange", "banana", "juice", "lemon", "melon", "raspberry", "strawberry", "smoothie",
    "1000ml", "500ml", "green", "fruit", "t-shirt", "mug", "sticker", "hoodie", "coaster", "card",
    "carrot", "eggfruit", "lemon juice", "apple pomace", "best juice", "owasp", "sweet", "",
]
REVIEWS = [
    "Tastes great, would buy again.", "A bit too sweet for me.", "Fast delivery and good quality.",
    "My kids love it!", "Fresh and natural taste.", "Good value for money.", "Packaging could be better.",
    "Nice design, comfy fit.", "Five stars from me.", "Not bad at all.",
]
def random_browser():
    """A realistic user agent from a wide spread of browsers and versions (old ones too).
    With only 5 fixed modern strings (first version) the classifier learned "unfamiliar browser = attacker"."""
    r = random.random()
    win = random.choice(["Windows NT 10.0; Win64; x64", "Windows NT 10.0; WOW64", "Windows NT 6.1; Win64; x64"])
    mac = f"Macintosh; Intel Mac OS X {random.choice(['10_15_7', '11_6', '12_6', '13_5', '14_6', '15_1'])}"
    if r < 0.45:                                   # Chrome / Chromium, versions 88-142
        v = random.randint(88, 142)
        plat = random.choice([win, win, mac, "X11; Linux x86_64", f"Linux; Android {random.randint(9, 15)}; {random.choice(['Pixel 7', 'SM-G991B', 'Pixel 9', 'Redmi Note 12'])}"])
        mobile = " Mobile" if "Android" in plat else ""
        return f"Mozilla/5.0 ({plat}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.{random.randint(4000, 7400)}.{random.randint(10, 200)}{mobile} Safari/537.36"
    if r < 0.65:                                   # Firefox 78-144
        v = random.randint(78, 144)
        plat = random.choice([win, mac.replace("_", "."), "X11; Linux x86_64", "X11; Ubuntu; Linux x86_64"])
        return f"Mozilla/5.0 ({plat}; rv:{v}.0) Gecko/20100101 Firefox/{v}.0"
    if r < 0.85:                                   # Safari, macOS and iOS 13-18
        v = random.randint(13, 18)
        if random.random() < 0.5:
            return f"Mozilla/5.0 (iPhone; CPU iPhone OS {v}_{random.randint(0, 6)} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{v}.{random.randint(0, 6)} Mobile/15E148 Safari/604.1"
        return f"Mozilla/5.0 ({mac}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{v}.{random.randint(0, 6)} Safari/605.1.15"
    v = random.randint(88, 142)                    # Edge
    return f"Mozilla/5.0 ({win}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36 Edg/{v}.0.{random.randint(1000, 3000)}.{random.randint(10, 99)}"



def rand_str(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class Shopper(HttpUser):
    wait_time = between(2, 8)          # think time between actions

    def on_start(self):
        self.client.headers["User-Agent"] = random_browser()
        self.client.headers["Accept-Language"] = random.choice(["en-US,en;q=0.9", "fr-FR,fr;q=0.8", "de-DE,de;q=0.7"])
        if random.random() < 0.6:                  # browsers send a Referer when navigating inside the app
            self.client.headers["Referer"] = "http://192.168.56.40/"
        self.token, self.basket_id, self.items, self.products = None, None, [], []
        # Wait for the target instead of dying: an exception here kills the user for good,
        # which is what happened when the host rebooted before the target VM was back.
        while not self.products:
            try:
                self.products = self.client.get("/api/Products", name="/api/Products").json().get("data", [])
            except Exception:
                time.sleep(30)
        self.email = f"{rand_str(8)}@{random.choice(['gmail.com', 'outlook.com', 'yahoo.fr', 'proton.me'])}"
        self.password = rand_str(10) + "A1!"
        r = self.client.post("/api/Users", name="/api/Users (register)", json={
            "email": self.email, "password": self.password, "passwordRepeat": self.password,
            "securityQuestion": {"id": random.randint(1, 14)}, "securityAnswer": rand_str(6)})
        if r.ok:
            self.login()

    def login(self):
        r = self.client.post("/rest/user/login", json={"email": self.email, "password": self.password})
        if r.ok:
            auth = r.json()["authentication"]
            self.token, self.basket_id = auth["token"], auth["bid"]
            self.client.headers["Authorization"] = f"Bearer {self.token}"

    # What the single-page app requests when a page loads
    @task(5)
    def home(self):
        self.client.get("/")
        self.client.get("/rest/admin/application-configuration")
        self.client.get("/rest/languages")
        self.client.get("/rest/products/search?q=", name="/rest/products/search?q=[all]")
        self.client.get("/api/Quantitys/")
        self.client.get(f"/socket.io/?EIO=4&transport=polling&t={rand_str(7)}", name="/socket.io/ (poll)")

    @task(6)
    def search(self):
        q = random.choice(SEARCH_TERMS)
        self.client.get(f"/rest/products/search?q={q}", name="/rest/products/search?q=[term]")

    @task(6)
    def view_product(self):
        if not self.products:
            return
        p = random.choice(self.products)
        self.client.get(f"/rest/products/{p['id']}/reviews", name="/rest/products/[id]/reviews")
        self.client.get(f"/assets/public/images/products/{p['image']}", name="/assets/.../products/[image]")

    @task(3)
    def add_to_basket(self):
        if not (self.token and self.products):
            return
        p = random.choice(self.products)
        r = self.client.post("/api/BasketItems/", json={"ProductId": p["id"], "BasketId": str(self.basket_id), "quantity": 1})
        if r.ok:
            self.items.append(r.json()["data"]["id"])
        self.client.get(f"/rest/basket/{self.basket_id}", name="/rest/basket/[id]")

    @task(2)
    def edit_basket(self):
        if not self.items:
            return
        item = random.choice(self.items)
        if random.random() < 0.7:
            self.client.put(f"/api/BasketItems/{item}", name="/api/BasketItems/[id]", json={"quantity": random.randint(1, 4)})
        else:
            self.client.delete(f"/api/BasketItems/{item}", name="/api/BasketItems/[id]")
            self.items.remove(item)

    @task(1)
    def write_review(self):
        if not (self.token and self.products):
            return
        p = random.choice(self.products)
        self.client.put(f"/rest/products/{p['id']}/reviews", name="/rest/products/[id]/reviews (write)",
                        json={"message": random.choice(REVIEWS), "author": self.email})

    @task(2)
    def account(self):
        if self.token:
            self.client.get("/rest/user/whoami")

    @task(1)
    def relogin(self):
        # Sessions end; users log back in (sometimes with a typo first, which real users do)
        if random.random() < 0.15:
            self.client.post("/rest/user/login", name="/rest/user/login (typo)",
                             json={"email": self.email, "password": self.password[:-1]})
            time.sleep(random.uniform(1, 3))
        self.login()
