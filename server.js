const express = require("express");
const fs = require("fs");
const cors = require("cors");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// Load blocklist
const blocklistFile = "blocklist.json";

app.get("/api/blocklist", (req, res) => {
    fs.readFile(blocklistFile, "utf8", (err, data) => {
        if (err) return res.status(500).send("Error reading blocklist.");
        res.json(JSON.parse(data));
    });
});

// Add a new domain
app.post("/api/blocklist", (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: "Domain required" });

    fs.readFile(blocklistFile, "utf8", (err, data) => {
        if (err) return res.status(500).send("Error reading blocklist.");
        let blocklist = JSON.parse(data);
        
        if (!blocklist.includes(domain)) {
            blocklist.push(domain);
            fs.writeFile(blocklistFile, JSON.stringify(blocklist, null, 2), (err) => {
                if (err) return res.status(500).send("Error updating blocklist.");
                res.json({ message: "Domain added", domain });
            });
        } else {
            res.status(400).json({ error: "Domain already blocked" });
        }
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
