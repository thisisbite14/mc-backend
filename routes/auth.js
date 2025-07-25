const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('../db');

const router = express.Router();

// เข้าสู่ระบบ
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

    if (rows.length === 0) {
      return res.status(401).json({ message: 'ไม่พบบัญชีผู้ใช้' });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ message: 'รหัสผ่านไม่ถูกต้อง' });
    }

    req.session.userId = user.id;
    res.json({ message: 'เข้าสู่ระบบสำเร็จ', user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในระบบ' });
  }
});

// ตรวจสอบว่า login อยู่ไหม
router.get('/me', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'ยังไม่ได้เข้าสู่ระบบ' });
  }

  res.json({ message: 'เข้าสู่ระบบอยู่', userId: req.session.userId });
});

// ออกจากระบบ
router.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'ออกจากระบบแล้ว' });
});

module.exports = router;

// สมัครสมาชิก
router.post('/register', async (req, res) => {
  const {
    prefix,
    first_name,
    last_name,
    email,
    password,
    faculty,
    role // ถ้าไม่ส่งมาจะใช้ DEFAULT ใน DB
  } = req.body;

  try {
    // ตรวจสอบ email ซ้ำ
    const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ message: 'อีเมลนี้ถูกใช้แล้ว' });
    }

    // เข้ารหัส password
    const hashedPassword = await bcrypt.hash(password, 10);

    // เพิ่มผู้ใช้ใหม่
    const [result] = await pool.query(
      `INSERT INTO users (prefix, first_name, last_name, email, password, faculty, role)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        prefix,
        first_name,
        last_name,
        email,
        hashedPassword,
        faculty || null,
        role || 'สมาชิก'
      ]
    );

    // สร้าง session ให้เลย
    req.session.userId = result.insertId;

    res.status(201).json({
      message: 'สมัครสมาชิกสำเร็จ',
      user: {
        id: result.insertId,
        email,
        name: `${prefix} ${first_name} ${last_name}`,
        role: role || 'สมาชิก',
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในระบบ' });
  }
});

router.get('/getUser', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'ยังไม่ได้เข้าสู่ระบบ' });
  }

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [req.session.userId]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
    }

    const user = rows[0];
    res.json({
      id: user.id,
      email: user.email,
      name: `${user.prefix} ${user.first_name} ${user.last_name}`,
      role: user.role,
      faculty: user.faculty
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในระบบ' });
  }
});

router.get('/getAllUsers', async (req, res) => {
  // ตรวจสอบว่าเข้าสู่ระบบแล้ว
  if (!req.session.userId) {
    return res.status(401).json({ message: 'ยังไม่ได้เข้าสู่ระบบ' });
  }

  try {
    // ตรวจสอบสิทธิ์ของผู้ใช้ปัจจุบัน (optional - ถ้าต้องการให้เฉพาะ admin)
    const [currentUser] = await pool.query('SELECT role FROM users WHERE id = ?', [req.session.userId]);
    
    if (currentUser.length === 0) {
      return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
    }

    // ถ้าต้องการให้เฉพาะ admin เข้าถึง ให้เปิด comment ด้านล่าง
    // if (currentUser[0].role !== 'admin') {
    //   return res.status(403).json({ message: 'ไม่มีสิทธิ์เข้าถึง' });
    // }

    // ดึงข้อมูลผู้ใช้ทั้งหมด (ไม่รวม password)
    const [users] = await pool.query(`
      SELECT 
        id, 
        prefix, 
        first_name, 
        last_name, 
        email, 
        faculty, 
        role, 
        created_at 
      FROM users 
      ORDER BY created_at DESC
    `);

    // จัดรูปแบบข้อมูล
    const formattedUsers = users.map(user => ({
      id: user.id,
      name: `${user.prefix} ${user.first_name} ${user.last_name}`,
      email: user.email,
      faculty: user.faculty,
      role: user.role,
      created_at: user.created_at
    }));

    res.json({
      message: 'ดึงข้อมูลผู้ใช้ทั้งหมดสำเร็จ',
      users: formattedUsers,
      total: formattedUsers.length
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในระบบ' });
  }
});

router.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'ออกจากระบบแล้ว' });
});

module.exports = router;