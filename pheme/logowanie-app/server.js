// server.js - OSTATECZNA WERSJA (MONGODB + MIGRACJA + BREVO API)
require("dotenv").config();
const mongoose = require('mongoose');
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const fs = require("fs"); 
const path = require("path");

const app = express();

// --- KONFIGURACJA Z .ENV ---
const SECRET = process.env.JWT_SECRET || "tajny_klucz_pheme_default";
const API_URL = process.env.API_URL || "https://pheme-far9.onrender.com";

// --- POŁĄCZENIE Z MONGOODB + AUTOMATYCZNY IMPORT STARYCH KONT ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
      console.log('✅ Połączono z bazą MongoDB! Dane są bezpieczne.');
      seedUsersFromJSON(); 
  })
  .catch((err) => console.error('❌ Błąd połączenia z MongoDB:', err));

// --- FUNKCJA WYSYŁANIA E-MAILI PRZEZ BREVO API (Omija blokady Rendera) ---
async function sendBrevoEmail(toEmail, subject, textContent, htmlContent) {
    try {
        const response = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: {
                'accept': 'application/json',
                'content-type': 'application/json',
                'api-key': process.env.BREVO_API_KEY // 🔑 Klucz dodany na Renderze
            },
            body: JSON.stringify({
                // 🔥 WAŻNE: Wpisz tutaj adres e-mail, którym logujesz się do Brevo!
                sender: { name: "Pheme App", email: "pheme.panel.studenta@gmail.com" }, 
                to: [{ email: toEmail }],
                subject: subject,
                textContent: textContent,
                htmlContent: htmlContent
            })
        });
        
        if (!response.ok) {
            const errData = await response.json();
            console.error("❌ Błąd Brevo API:", errData);
        } else {
            console.log(`✉️ Mail (Brevo) wysłany pomyślnie do: ${toEmail}`);
        }
    } catch (e) {
        console.error("❌ Błąd połączenia z Brevo:", e);
    }
}

// --- MODELE BAZY DANYCH (MONGOOSE SCHEMAS) ---
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    name: { type: String, default: "" },
    role: { type: String, default: "user" },
    email: { type: String, default: "" }
});
const User = mongoose.model('User', userSchema);

// --- FUNKCJA PRZEPISUJĄCA OSOBY Z users.json DO MONGODB ---
async function seedUsersFromJSON() {
    try {
        const filePath = path.join(__dirname, "users.json");
        if (fs.existsSync(filePath)) {
            const rawData = fs.readFileSync(filePath, "utf8");
            const localUsers = JSON.parse(rawData);
            let importedCount = 0;
            
            for (const localUser of localUsers) {
                const exists = await User.findOne({ username: localUser.username });
                if (!exists) {
                    const newUser = new User({
                        username: localUser.username,
                        password: localUser.password,
                        name: localUser.name || "",
                        role: localUser.role || "user",
                        email: localUser.email || ""
                    });
                    await newUser.save();
                    importedCount++;
                }
            }
            if (importedCount > 0) {
                console.log(`📥 Sukces! Pomyślnie przeniesiono ${importedCount} użytkowników do MongoDB.`);
            } else {
                console.log("ℹ️ Wszyscy użytkownicy z pliku users.json są już w MongoDB.");
            }
        } else {
            console.log("⚠️ Nie znaleziono pliku users.json.");
        }
    } catch (error) {
        console.error("❌ Błąd podczas automatycznego importu kont:", error);
    }
}

const sectionSchema = new mongoose.Schema({
    name: String,
    code: { type: String, unique: true },
    creator: String,
    joinEnabled: { type: Boolean, default: true },
    members: [{ username: String, role: String }],
    notes: [{ id: Number, lessonName: String, link1: String, link2: String, date: String }],
    feedbacks: [{ id: String, lessonName: String, message: String, username: String, author: String, date: String, edited: Boolean }],
    questions: [{
        id: String,
        from: String,
        fromUsername: String,
        subject: String,
        text: String,
        to: [String],
        date: String,
        replies: [{ from: String, fromUsername: String, text: String, date: String }]
    }]
});
const Section = mongoose.model('Section', sectionSchema);

app.use(express.json());
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.static(__dirname));

const loginLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 1000,
    message: "Zbyt wiele prób logowania. Spróbuj później.",
    standardHeaders: true,
    legacyHeaders: false,
});

// --- MIDDLEWARE ---
function auth(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).send("Brak tokena");
    const token = header.split(" ")[1];
    try {
        req.user = jwt.verify(token, SECRET);
        next();
    } catch {
        res.status(401).send("Zły token");
    }
}

function admin(req, res, next) {
    if (req.user.role !== "admin" && req.user.role !== "polska_sigma") return res.status(403).send("Brak dostępu");
    next();
}

function godAuth(req, res, next) {
    if (req.user.role !== "polska_sigma") return res.status(403).json({ message: "Brak uprawnień boskich!" });
    next();
}

// --- ENDPOINTY UŻYTKOWNIKÓW ---
app.post("/register", async (req, res) => {
    try {
        const { username, password, name } = req.body;
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).send("Użytkownik już istnieje");
        
        const hash = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hash, name: name || "", role: "user", email: "" });
        await newUser.save();
        
        res.send("Zarejestrowano!");
    } catch (e) { res.status(500).send("Błąd serwera"); }
});

app.post("/login", loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(400).send("Brak użytkownika");
        
        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(400).send("Złe hasło");
        
        const token = jwt.sign({ username: user.username, role: user.role }, SECRET, { expiresIn: "7d" });
        res.json({ token });
    } catch (e) { res.status(500).send("Błąd serwera"); }
});

app.get("/profil", auth, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.user.username });
        if (!user) return res.status(404).send("User not found");
        res.json({ username: user.username, name: user.name || "", role: user.role, email: user.email || "" });
    } catch (e) { res.status(500).send("Błąd serwera"); }
});

app.post("/update-profile", auth, async (req, res) => {
    try {
        const { newName, email, oldPassword, newPassword } = req.body;
        const user = await User.findOne({ username: req.user.username });
        if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje" });
        
        if (newName && newName.trim() !== "") user.name = newName;
        if (email !== undefined) user.email = email.trim(); 

        if (newPassword && newPassword.trim() !== "") {
            if (!oldPassword) return res.status(400).json({ message: "Podaj stare hasło" });
            const passwordMatch = await bcrypt.compare(oldPassword, user.password);
            if (!passwordMatch) return res.status(401).json({ message: "Stare hasło nieprawidłowe" });
            user.password = await bcrypt.hash(newPassword, 10);
        }
        await user.save();
        res.json({ message: "Pomyślnie zaktualizowano profil" });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.post("/promote-global", auth, async (req, res) => {
    try {
        const { targetUsername } = req.body;
        const requesterRole = req.user.role;

        if (requesterRole !== "polska_sigma") return res.status(403).json({ message: "Brak globalnych uprawnień boga!" });

        const user = await User.findOne({ username: targetUsername });
        if (!user) return res.status(404).json({ message: "Nie znaleziono takiego użytkownika w bazie." });

        if (user.role === "user") {
            user.role = "admin";
            await user.save();
            return res.json({ message: `Użytkownik ${targetUsername} został awansowany na Admina!` });
        } 
        
        if (user.role === "admin") {
            user.role = "polska_sigma";
            await user.save();
            return res.json({ message: `Użytkownik ${targetUsername} Został Polską Sigmą` });
        }

        res.status(400).json({ message: "Ten użytkownik posiada już najwyższą możliwą rangę (Polska Sigma)." });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.post("/demote-global", auth, async (req, res) => {
    try {
        const { targetUsername } = req.body;
        const requesterUsername = req.user.username;

        if (requesterUsername !== "pomaksik") return res.status(403).json({ message: "Brak uprawnień. Tylko pomaksik posiada moc odbierania rang!" });
        if (targetUsername === "pomaksik") return res.status(400).json({ message: "Nie możesz zdegradować samego siebie!" });

        const user = await User.findOne({ username: targetUsername });
        if (!user) return res.status(404).json({ message: "Nie znaleziono takiego użytkownika w bazie." });

        if (user.role === "polska_sigma") {
            user.role = "admin";
            await user.save();
            return res.json({ message: `Użytkownik ${targetUsername} został zdegradowany do rangi Admin.` });
        } 
        
        if (user.role === "admin") {
            user.role = "user";
            await user.save();
            return res.json({ message: `Użytkownik ${targetUsername} został zdegradowany do rangi Użytkownik (user).` });
        }

        res.status(400).json({ message: "Ten użytkownik ma już najniższą możliwą rangę (user)." });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

// --- SEKCE ---
app.post("/create-section", auth, admin, async (req, res) => {
    try {
        const { name, code } = req.body;
        const existingSection = await Section.findOne({ code });
        if (existingSection) return res.status(400).json({ message: "Sekcja już istnieje" });
        
        const newSection = new Section({
            name,
            code,
            creator: req.user.username,
            members: [{ username: req.user.username, role: "nauczyciel" }],
            notes: [],
            feedbacks: [],
            questions: [],
            joinEnabled: true
        });
        await newSection.save();
        res.json({ message: "Sekcja utworzona pomyślnie!", code });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.post("/join-section", auth, async (req, res) => {
    try {
        const { code } = req.body;
        const section = await Section.findOne({ code });
        if (!section) return res.status(404).json({ message: "Zły kod sekcji" });
        
        if (section.joinEnabled === false) return res.status(403).json({ message: "Dołączanie do tej sekcji zostało zablokowane przez nauczyciela." });
        if (section.members.find(m => m.username === req.user.username)) return res.status(400).json({ message: "Już tu jesteś!" });
        
        section.members.push({ username: req.user.username, role: "user" });
        await section.save();
        res.json({ message: "Dołączono do sekcji: " + section.name });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.get("/moje-sekcje", auth, async (req, res) => {
    try {
        const sections = await Section.find({ "members.username": req.user.username });
        const mySections = sections.map(s => ({
            name: s.name,
            kod: s.code,
            rola: s.members.find(m => m.username === req.user.username).role,
            joinEnabled: s.joinEnabled !== false 
        }));
        res.json(mySections);
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.get('/section-members/:code', auth, async (req, res) => {
    try {
        const { code } = req.params;
        const section = await Section.findOne({ code });
        if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });

        const usernames = section.members.map(m => m.username);
        const users = await User.find({ username: { $in: usernames } });

        const memberDetails = section.members.map(m => {
            const user = users.find(u => u.username === m.username);
            return {
                username: m.username,
                name: user ? user.name : m.username,
                role: m.role
            };
        });
        res.json(memberDetails);
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

// --- LEKCJE / NOTATKI ---
app.get("/section-notes/:code", auth, async (req, res) => {
    try {
        const section = await Section.findOne({ code: req.params.code });
        if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
        res.json(section.notes || []);
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.post("/toggle-section-join", auth, async (req, res) => {
    try {
        const { code } = req.body;
        const section = await Section.findOne({ code });
        if (!section) return res.status(404).json({ message: "Sekcja nie istnieje." });
        
        const member = section.members.find(m => m.username === req.user.username);
        if (!member || member.role !== "nauczyciel") return res.status(403).json({ message: "Brak uprawnień. Tylko nauczyciel sekcji może to zrobić." });

        section.joinEnabled = !section.joinEnabled;
        await section.save();

        res.json({ 
            message: section.joinEnabled ? "Odblokowano dołączanie 🔓" : "Zablokowano dołączanie 🔒", 
            joinEnabled: section.joinEnabled 
        });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.post("/add-note", auth, async (req, res) => {
    try {
        const { code, lessonName, link1, link2 } = req.body;
        const section = await Section.findOne({ code });
        if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
        
        const member = section.members.find(m => m.username === req.user.username);
        if (!member || (member.role !== "nauczyciel" && req.user.role !== "admin" && req.user.role !== "polska_sigma")) {
            return res.status(403).json({ message: "Brak uprawnień" });
        }
        
        section.notes.push({ id: Date.now(), lessonName, link1, link2, date: new Date().toISOString().split('T')[0] });
        await section.save();
        res.json({ message: "Notatka dodana!" });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.delete("/delete-note/:code/:noteId", auth, async (req, res) => {
    try {
        const { code, noteId } = req.params;
        const section = await Section.findOne({ code });
        if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
        
        const member = section.members.find(m => m.username === req.user.username);
        const isGod = req.user.role === "admin" || req.user.role === "polska_sigma";
        
        if (!isGod && (!member || member.role !== "nauczyciel")) return res.status(403).json({ message: "Brak uprawnień" });
        
        section.notes = section.notes.filter(n => n.id.toString() !== noteId.toString());
        await section.save();
        res.json({ message: "Usunięto lekcję" });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.delete("/god/delete-section/:code", auth, godAuth, async (req, res) => {
    try {
        const result = await Section.deleteOne({ code: req.params.code });
        if (result.deletedCount === 0) return res.status(404).json({ message: "Nie ma takiej sekcji!" });
        res.json({ message: "Sekcja została CAŁKOWICIE ZNISZCZONA z bazy danych." });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

// --- SYSTEM FEEDBACKU ---
app.post('/add-feedback', auth, async (req, res) => {
    try {
        const { code, lessonName, message } = req.body;
        const section = await Section.findOne({ code });
        const user = await User.findOne({ username: req.user.username });

        if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });

        const newFeedback = {
            id: Date.now().toString(),
            lessonName,
            message,
            username: req.user.username,
            author: user.name || req.user.username,
            date: new Date().toLocaleString(),
            edited: false
        };

        section.feedbacks.push(newFeedback);
        await section.save();
        res.json({ message: "Feedback dodany!" });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.get("/section-feedback/:code", auth, async (req, res) => {
    try {
        const section = await Section.findOne({ code: req.params.code });
        if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
        
        const member = section.members.find(m => m.username === req.user.username);
        const isTeacher = member && member.role === "nauczyciel";
        const isAdmin = (req.user.role === "admin" || req.user.role === "polska_sigma");
        const allFbs = section.feedbacks || [];

        if (isTeacher || isAdmin) {
            res.json(allFbs);
        } else {
            res.json(allFbs.filter(f => f.username === req.user.username));
        }
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.post('/edit-feedback', auth, async (req, res) => {
    try {
        const { code, lessonName, newMessage } = req.body;
        const section = await Section.findOne({ code });
        if (!section || !section.feedbacks) return res.status(404).json({ message: "Błąd sekcji" });

        const fb = section.feedbacks.find(f => f.lessonName === lessonName && f.username === req.user.username);
        if (fb) {
            fb.message = newMessage;
            fb.edited = true;
            fb.date = new Date().toLocaleString() + " (edytowano)";
            section.markModified('feedbacks');
            await section.save();
            return res.json({ message: "Zaktualizowano feedback" });
        }
        res.status(404).json({ message: "Nie znaleziono Twojej opinii do edycji" });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.post("/promote-to-teacher", auth, async (req, res) => {
    try {
        const { code, targetUsername } = req.body;
        const section = await Section.findOne({ code });
        if (!section) return res.status(404).json({ message: "Nie znaleziono sekcji" });

        const meInSection = section.members.find(m => m.username === req.user.username);
        const isGlobalAdmin = (req.user.role === "admin" || req.user.role === "polska_sigma");
        const isSectionTeacher = meInSection && meInSection.role === "nauczyciel";

        if (!(isGlobalAdmin && isSectionTeacher)) return res.status(403).json({ message: "Musisz być jednocześnie Adminem i Nauczycielem sekcji." });

        const targetMember = section.members.find(m => m.username === targetUsername);
        if (!targetMember) return res.status(404).json({ message: "Użytkownik nie należy do tej sekcji" });

        targetMember.role = "nauczyciel";
        section.markModified('members');
        await section.save();
        res.json({ message: `Użytkownik ${targetUsername} został mianowany nauczycielem!` });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

// --- SYSTEM PYTAŃ (POWIADOMIENIA BREVO) ---
app.post("/ask-question", auth, async (req, res) => {
    try {
        const { code, subject, question, recipients } = req.body; 
        const section = await Section.findOne({ code });
        if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });

        const user = await User.findOne({ username: req.user.username });
        const newQuestion = {
            id: Date.now().toString(), 
            from: user.name || user.username,
            fromUsername: user.username,
            subject: subject || "Brak tematu",
            text: question,
            to: recipients,
            date: new Date().toLocaleString("pl-PL"),
            replies: [] 
        };

        section.questions.push(newQuestion);
        await section.save();

        process.nextTick(async () => {
            const targetLogins = Array.isArray(recipients) ? recipients : [recipients];
            const teachers = await User.find({ username: { $in: targetLogins } });
            
            teachers.forEach(teacherUser => {
                if (teacherUser && teacherUser.email && teacherUser.email.trim() !== "") {
                    
                    const mailSubject = `[Pheme] Nowa wiadomość od ${user.name || user.username}!`;
                    const mailText = `Cześć ${teacherUser.name || teacherUser.username}!\n\nUżytkownik ${user.name || user.username} napisał do Ciebie wiadomość w sekcji ${section.name}:\n\nTemat: "${newQuestion.subject}"\nTreść: "${newQuestion.text}"\n\nZaloguj się do platformy, aby odpowiedzieć:\n${API_URL}`;
                    const mailHtml = `
                        <h3>Cześć ${teacherUser.name || teacherUser.username}!</h3>
                        <p>Użytkownik <strong>${user.name || user.username}</strong> napisał do Ciebie wiadomość w sekcji <strong>${section.name}</strong>:</p>
                        <blockquote style="border-left: 4px solid #00ce52; padding: 10px; background: #f9f9f9; color: #333;">
                            <strong>Temat:</strong> ${newQuestion.subject}<br>
                            <strong>Treść:</strong> ${newQuestion.text}
                        </blockquote>
                        <p><a href="${API_URL}/pytania.html">Kliknij tutaj, aby przejść do Centrum Wiadomości i odpowiedzieć</a>.</p>
                    `;

                    sendBrevoEmail(teacherUser.email, mailSubject, mailText, mailHtml);
                }
            });
        });

        res.json({ message: "Pytanie wysłane!" });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.get("/section-questions/:code", auth, async (req, res) => {
    try {
        const section = await Section.findOne({ code: req.params.code });
        if (!section) return res.status(404).json({ message: "Błąd" });

        const allQs = section.questions || [];
        const myUsername = req.user.username;

        if (req.user.role === "polska_sigma" || req.user.role === "admin") return res.json(allQs);

        const filtered = allQs.filter(q => q.fromUsername === myUsername || q.to.includes(myUsername));
        res.json(filtered);
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.post("/reply-question", auth, async (req, res) => {
    try {
        const { code, questionId, text } = req.body;
        const section = await Section.findOne({ code });
        if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });

        const question = section.questions.find(q => q.id === questionId || q.id.toString() === questionId);
        if (!question) return res.status(404).json({ message: "Nie znaleziono wątku" });

        const user = await User.findOne({ username: req.user.username });
        const replyDate = new Date().toLocaleString("pl-PL");

        question.replies.push({
            from: user.name || user.username,
            fromUsername: user.username,
            text: text,
            date: replyDate
        });

        section.markModified('questions');
        await section.save();

        process.nextTick(async () => {
            let participantsLogins = new Set();
            participantsLogins.add(question.fromUsername); 
            if (Array.isArray(question.to)) question.to.forEach(u => participantsLogins.add(u)); 
            else participantsLogins.add(question.to);
            
            participantsLogins.delete(user.username);
            const targets = await User.find({ username: { $in: Array.from(participantsLogins) } });

            targets.forEach(targetUser => {
                if (targetUser && targetUser.email && targetUser.email.trim() !== "") {

                    const mailSubject = `[Pheme] Nowa odpowiedź w sekcji: ${section.name}`;
                    const mailText = `Witaj ${targetUser.name || targetUser.username}!\n\nUżytkownik ${user.name || user.username} odpowiedział na Twoją konwersację w sekcji "${section.name}" (Data: ${replyDate}).\n\nTemat: ${question.subject}\nTreść odpowiedzi: "${text}"\n\nZaloguj się do platformy, aby zobaczyć i odpowiedzieć:\n${API_URL}/pytania.html`;
                    const mailHtml = `
                        <h3>Witaj ${targetUser.name || targetUser.username}!</h3>
                        <p>Użytkownik <strong>${user.name || user.username}</strong> odpowiedział na Twoją konwersację w sekcji <strong>${section.name}</strong> (Data: ${replyDate}).</p>
                        <p><strong>Temat:</strong> ${question.subject}</p>
                        <blockquote style="border-left: 4px solid #007bff; padding: 10px; background: #f9f9f9; color: #333;">
                            <strong>Treść odpowiedzi:</strong><br>${text}
                        </blockquote>
                        <p><a href="${API_URL}/pytania.html">Kliknij tutaj, aby przejść do Centrum Wiadomości i odpisać</a>.</p>
                    `;

                    sendBrevoEmail(targetUser.email, mailSubject, mailText, mailHtml);
                }
            });
        });
        
        res.json({ message: "Dodano odpowiedź!" });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.post("/remove-from-section", auth, async (req, res) => {
    try {
        const { code, targetUsername } = req.body;
        const requesterUsername = req.user.username; 
        const requesterGlobalRole = req.user.role;

        const section = await Section.findOne({ code });
        if (!section) return res.status(404).json({ message: "Nie znaleziono sekcji." });

        const memberInSec = section.members.find(m => m.username === requesterUsername);
        const isSectionTeacher = memberInSec && memberInSec.role === "nauczyciel";
        const isGod = requesterGlobalRole === "polska_sigma" || requesterGlobalRole === "admin";

        if (!isGod && !isSectionTeacher) return res.status(403).json({ message: "Brak uprawnień." });
        if (targetUsername === requesterUsername) return res.status(400).json({ message: "Nie możesz usunąć z sekcji samego siebie w ten sposób." });
        
        const targetUser = await User.findOne({ username: targetUsername });
        if (targetUser && targetUser.role === "polska_sigma") return res.status(403).json({ message: "Żałosna próba. Nie możesz wyrzucić Polskiej Sigmy!" });

        const memberIndex = section.members.findIndex(m => m.username === targetUsername);
        if (memberIndex === -1) return res.status(404).json({ message: "Użytkownik nie jest w tej sekcji." });

        section.members.splice(memberIndex, 1);
        await section.save();

        res.json({ message: `Usunięto użytkownika ${targetUsername}.` });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

// ==========================================
// --- PANEL BOGA (SIGMY) --- Only Polska Sigma
// ==========================================
app.get("/god/all-users", auth, godAuth, async (req, res) => {
    try {
        const users = await User.find({}, 'username name role email');
        res.json(users);
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.get("/god/all-sections", auth, godAuth, async (req, res) => {
    try {
        const sections = await Section.find({});
        res.json(sections);
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.get("/god/all-feedbacks", auth, godAuth, async (req, res) => {
    try {
        const sections = await Section.find({});
        let allFb = [];
        sections.forEach(s => {
            (s.feedbacks || []).forEach(f => {
                allFb.push({ id: f.id, lessonName: f.lessonName, message: f.message, username: f.username, author: f.author, date: f.date, edited: f.edited, sectionCode: s.code, sectionName: s.name });
            });
        });
        res.json(allFb.reverse()); 
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.get("/god/all-questions", auth, godAuth, async (req, res) => {
    try {
        const sections = await Section.find({});
        let allQ = [];
        sections.forEach(s => {
            (s.questions || []).forEach(q => {
                allQ.push({ id: q.id, from: q.from, fromUsername: q.fromUsername, subject: q.subject, text: q.text, to: q.to, date: q.date, replies: q.replies, sectionCode: s.code, sectionName: s.name });
            });
        });
        res.json(allQ.reverse()); 
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.post("/god/delete-user", auth, godAuth, async (req, res) => {
    try {
        const { targetUsername } = req.body;

        const user = await User.findOne({ username: targetUsername });
        if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje w bazie." });
        if (user.role === "admin") return res.status(403).json({ message: "Nie można usuwać innych administratorów." });

        await User.deleteOne({ username: targetUsername });

        const sections = await Section.find({ "members.username": targetUsername });
        for (let s of sections) {
            s.members = s.members.filter(m => m.username !== targetUsername);
            await s.save();
        }

        res.json({ message: `Użytkownik ${targetUsername} został pomyślnie usunięty.` });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

app.post("/god/force-add-member", auth, godAuth, async (req, res) => {
    try {
        const { username, code, role } = req.body;
        const section = await Section.findOne({ code });
        if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
        
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje w bazie" });

        const existingMember = section.members.find(m => m.username === username);
        if (existingMember) {
            existingMember.role = role; 
            section.markModified('members');
        } else {
            section.members.push({ username, role });
        }
        await section.save();
        res.json({ message: `Użytkownik ${username} został dodany jako ${role} do sekcji ${section.name}` });
    } catch (e) { res.status(500).json({ message: "Błąd serwera" }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Serwer działa na porcie " + PORT));