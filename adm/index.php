<?php
// CMS Portal Lowongan Kerja dengan Backend PHP
// File: index.php

// ---- Start session sebelum output apapun ----
session_start();
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32)); // CSRF token
}

// ===== Koneksi database =====
$host     = 'localhost';
$port     = 3306;
$dbname   = 'jadg5831_job_board';
$username = 'jadg5831_job_portal';
$password = 'hRRPHI%VNXjBw8,E';

$dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset=utf8mb4";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $username, $password, $options);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// ===== Utility =====
function clean_input($data) {
    $data = trim((string)$data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

// ===== Query helpers =====
function get_all_jobs(PDO $pdo, $status = 'active') {
    $stmt = $pdo->prepare("SELECT * FROM lowongan WHERE status = :status ORDER BY tanggal_post DESC");
    $stmt->bindParam(':status', $status);
    $stmt->execute();
    return $stmt->fetchAll();
}

function get_pending_jobs(PDO $pdo) {
    $stmt = $pdo->query("SELECT * FROM lowongan WHERE status = 'pending' ORDER BY tanggal_post DESC");
    return $stmt->fetchAll();
}

function update_job_status(PDO $pdo, int $id, string $status) {
    $stmt = $pdo->prepare("UPDATE lowongan SET status = :status WHERE id = :id");
    $stmt->bindParam(':status', $status);
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    return $stmt->execute();
}

function add_new_job(PDO $pdo, array $data) {
    $stmt = $pdo->prepare("INSERT INTO lowongan 
        (id_kategori, judul, deskripsi, tanggal_post, tanggal_akhir, perusahaan, lokasi, status, contact_email) 
        VALUES 
        (:id_kategori, :judul, :deskripsi, CURDATE(), :tanggal_akhir, :perusahaan, :lokasi, 'pending', :contact_email)");
    
    return $stmt->execute([
        ':id_kategori'    => $data['id_kategori'],
        ':judul'          => $data['judul'],
        ':deskripsi'      => $data['deskripsi'],
        ':tanggal_akhir'  => $data['tanggal_akhir'],
        ':perusahaan'     => $data['perusahaan'],
        ':lokasi'         => $data['lokasi'],
        ':contact_email'  => $data['contact_email']
    ]);
}

function delete_job(PDO $pdo, int $id) {
    $stmt = $pdo->prepare("DELETE FROM lowongan WHERE id = :id");
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    return $stmt->execute();
}

// ---------- LOGIN HELPER (final) ----------
function admin_login(PDO $pdo, string $username, string $password): ?array {
    $st = $pdo->prepare("SELECT id, username, password FROM users WHERE username = ? LIMIT 1");
    $st->execute([$username]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if (!$row) return null;

    $stored = (string)$row['password'];
    $ok = false;

    // Hash modern (bcrypt/argon2)
    if (preg_match('/^\$2y\$/', $stored) || strncmp($stored, '$argon2', 7) === 0) {
        $ok = password_verify($password, $stored);
        if ($ok && password_needs_rehash($stored, PASSWORD_DEFAULT)) {
            $new = password_hash($password, PASSWORD_DEFAULT);
            $u = $pdo->prepare("UPDATE users SET password=? WHERE id=?");
            $u->execute([$new, (int)$row['id']]);
        }
    }
    // Legacy MD5
    elseif (preg_match('/^[a-f0-9]{32}$/i', $stored)) {
        $ok = hash_equals($stored, md5($password));
        if ($ok) {
            $new = password_hash($password, PASSWORD_DEFAULT);
            $u = $pdo->prepare("UPDATE users SET password=? WHERE id=?");
            $u->execute([$new, (int)$row['id']]);
        }
    }
    // Legacy plaintext
    else {
        $ok = hash_equals($stored, $password);
        if ($ok) {
            $new = password_hash($password, PASSWORD_DEFAULT);
            $u = $pdo->prepare("UPDATE users SET password=? WHERE id=?");
            $u->execute([$new, (int)$row['id']]);
        }
    }

    return $ok ? ['id' => (int)$row['id'], 'username' => $row['username']] : null;
}
// ---------- END LOGIN HELPER ----------

// ===== Logout =====
if (isset($_GET['logout'])) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params['path'], $params['domain'],
            $params['secure'], $params['httponly']
        );
    }
    session_destroy();
    header("Location: index.php");
    exit();
}

// ====== LOGIN HANDLER (INI YANG KEMARIN HILANG) ======
if (isset($_POST['login'])) {
    $u = clean_input($_POST['username'] ?? '');
    $p = (string)($_POST['password'] ?? '');
    $user = admin_login($pdo, $u, $p);
    if ($user) {
        session_regenerate_id(true);
        $_SESSION['admin_id'] = $user['id'];
        $_SESSION['admin_username'] = $user['username'];
        header("Location: index.php");
        exit();
    } else {
        $error_message = "Username atau password salah!";
    }
}

// ===== Proses aksi admin (CRUD & CHANGE PASSWORD) =====
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    // Validasi CSRF
    $csrf = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $csrf)) {
        $error_message = "Sesi kedaluwarsa. Coba lagi.";
    } elseif (!isset($_SESSION['admin_id'])) {
        $error_message = "Anda harus login terlebih dahulu!";
    } else {
        $action = $_POST['action'];

        if ($action === 'add_job') {
            $job_data = [
                'id_kategori'   => clean_input($_POST['id_kategori'] ?? ''),
                'judul'         => clean_input($_POST['judul'] ?? ''),
                'deskripsi'     => clean_input($_POST['deskripsi'] ?? ''),
                'tanggal_akhir' => clean_input($_POST['tanggal_akhir'] ?? ''),
                'perusahaan'    => clean_input($_POST['perusahaan'] ?? ''),
                'lokasi'        => clean_input($_POST['lokasi'] ?? ''),
                'contact_email' => clean_input($_POST['contact_email'] ?? '')
            ];
            if (add_new_job($pdo, $job_data)) {
                $success_message = "Lowongan berhasil diajukan! Menunggu persetujuan admin.";
            } else {
                $error_message = "Gagal mengajukan lowongan. Silakan coba lagi.";
            }

        } elseif ($action === 'approve_job') {
            if (update_job_status($pdo, (int)$_POST['job_id'], 'active')) {
                $success_message = "Lowongan berhasil disetujui!";
            } else {
                $error_message = "Gagal menyetujui lowongan.";
            }

        } elseif ($action === 'reject_job') {
            if (update_job_status($pdo, (int)$_POST['job_id'], 'rejected')) {
                $success_message = "Lowongan berhasil ditolak!";
            } else {
                $error_message = "Gagal menolak lowongan.";
            }

        } elseif ($action === 'delete_job') {
            if (delete_job($pdo, (int)$_POST['job_id'])) {
                $success_message = "Lowongan berhasil dihapus!";
            } else {
                $error_message = "Gagal menghapus lowongan.";
            }

        } elseif ($action === 'change_password') {
            $current = (string)($_POST['current_password'] ?? '');
            $new1    = (string)($_POST['new_password'] ?? '');
            $new2    = (string)($_POST['confirm_password'] ?? '');

            if ($new1 === '' || $current === '') {
                $error_message = "Isi semua kolom password.";
            } elseif ($new1 !== $new2) {
                $error_message = "Konfirmasi password tidak sama.";
            } elseif (strlen($new1) < 8) {
                $error_message = "Password baru minimal 8 karakter.";
            } else {
                // Verifikasi password lama pakai admin_login
                $meUsername = $_SESSION['admin_username'];
                $me = admin_login($pdo, $meUsername, $current);
                if (!$me) {
                    $error_message = "Password lama salah.";
                } else {
                    $hash = password_hash($new1, PASSWORD_DEFAULT);
                    $u = $pdo->prepare("UPDATE users SET password=? WHERE id=?");
                    $u->execute([$hash, (int)$_SESSION['admin_id']]);
                    $success_message = "Password berhasil diubah.";
                }
            }
        }
    }
}

// ===== Data untuk tampilan =====
$active_jobs  = get_all_jobs($pdo, 'active');
$pending_jobs = get_pending_jobs($pdo);
$kategori     = $pdo->query("SELECT * FROM kategori")->fetchAll();
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JobPortal CMS - Sistem Manajemen Lowongan Kerja</title>

    <!-- Pakai file CSS eksternal jika ada di folder yang sama -->
    <link rel="stylesheet" href="style.css">

    <!-- Fallback CSS inline (dipakai hanya jika style.css tidak ditemukan) -->
    <style>
    <?php if (!is_file(__DIR__ . '/style.css')): ?>
        :root{--bg:#0f172a;--muted:#1e293b;--card:#111827;--text:#e5e7eb;--sub:#cbd5e1;--accent:#22c55e;--danger:#ef4444;--warn:#f59e0b}
        *{box-sizing:border-box}html,body{margin:0;padding:0}body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;background:var(--bg);color:var(--text)}
        a{color:inherit;text-decoration:none}
        .login-container{min-height:100vh;display:grid;place-items:center;padding:24px}
        .login-form{background:var(--card);width:min(420px,92vw);padding:28px;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
        .login-form h2{margin:0 0 16px}
        .form-group{margin:12px 0}
        .form-group label{display:block;margin-bottom:6px;color:var(--sub);font-size:14px}
        .form-control{width:100%;padding:12px 14px;border:1px solid #374151;border-radius:12px;background:#0b1220;color:var(--text)}
        .btn{display:inline-flex;align-items:center;gap:8px;border:0;border-radius:12px;padding:10px 14px;cursor:pointer}
        .btn-primary{background:var(--accent);color:#0a0f1c;font-weight:600}
        .container{display:grid;grid-template-columns:260px 1fr;min-height:100vh}
        .sidebar{background:#0b1220;border-right:1px solid #1f2937;padding:18px;position:sticky;top:0;height:100vh}
        .logo{display:flex;align-items:center;gap:10px;margin-bottom:18px}
        .nav-links{list-style:none;margin:0;padding:0}
        .nav-links li{margin:6px 0}
        .nav-links a{display:flex;gap:10px;align-items:center;padding:10px 12px;border-radius:12px;color:var(--sub)}
        .nav-links a.active,.nav-links a:hover{background:#13203a;color:var(--text)}
        .main-content{padding:18px}
        .header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
        .stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:14px 0}
        .stat-card{display:flex;gap:14px;align-items:center;background:var(--card);padding:16px;border-radius:16px;border:1px solid #1f2937}
        .stat-icon i{font-size:22px}
        .panel{background:var(--card);border:1px solid #1f2937;border-radius:16px;margin:16px 0}
        .panel-header{padding:14px 16px;border-bottom:1px solid #1f2937}
        .panel-body{padding:16px}
        .empty-state{display:grid;place-items:center;padding:24px;color:var(--sub)}
        .table{width:100%;border-collapse:separate;border-spacing:0;margin:0}
        .table th,.table td{padding:12px 10px;border-bottom:1px solid #1f2937;text-align:left}
        .table thead th{color:var(--sub);font-weight:600}
        .action-btn{padding:8px 10px;border-radius:10px;border:1px solid #1f2937;background:#0b1220;color:var(--text);cursor:pointer}
        .action-btn.delete{border-color:#3a1e1e;background:#1b0f0f;color:#ffb4b4}
        .alert{border-radius:12px;padding:10px 12px;margin:10px 0}
        .alert.success{background:#10261b;color:#b7f0c2;border:1px solid #1f4730}
        .alert.error{background:#2a1414;color:#ffb4b4;border:1px solid #532222}
        .form-row{display:grid;gap:12px;grid-template-columns:repeat(2,minmax(0,1fr))}
        .form-footer{margin-top:10px}
        .footer-powered{margin:22px 0;text-align:center;color:var(--sub);font-size:13px}
        @media (max-width:900px){.container{grid-template-columns:1fr}.sidebar{position:relative;height:auto}.stats{grid-template-columns:1fr}.form-row{grid-template-columns:1fr}}
    <?php endif; ?>
    </style>

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
<?php if (!isset($_SESSION['admin_id'])): ?>
    <!-- ===== Form Login ===== -->
    <div class="login-container">
        <form method="post" class="login-form">
            <h2><i class="fas fa-lock"></i> Admin Login</h2>

            <?php if (isset($error_message)): ?>
                <div class="alert error">
                    <i class="fas fa-exclamation-circle"></i> <?= $error_message; ?>
                </div>
            <?php endif; ?>

            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" class="form-control" required autocomplete="username">
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" class="form-control" required autocomplete="current-password">
            </div>

            <button type="submit" name="login" class="btn btn-primary">
                <i class="fas fa-sign-in-alt"></i> Login
            </button>
        </form>
        <footer class="footer-powered">Powered by <strong>UniverseRIA</strong></footer>
    </div>
<?php else: ?>
    <!-- ===== Tampilan Admin ===== -->
    <div class="container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="logo">
                <i class="fas fa-briefcase"></i>
                <h1>JobPortal CMS</h1>
            </div>
            <ul class="nav-links">
                <li><a href="#" class="active"><i class="fas fa-home"></i> <span>Dashboard</span></a></li>
                <li><a href="#jobs"><i class="fas fa-list"></i> <span>Lowongan Aktif</span></a></li>
                <li><a href="#pending"><i class="fas fa-clock"></i> <span>Pengajuan Lowongan</span></a></li>
                <li><a href="#add-job"><i class="fas fa-plus"></i> <span>Tambah Lowongan</span></a></li>
                <li><a href="#account"><i class="fas fa-user-shield"></i> <span>Akun & Password</span></a></li>
                <li><a href="index.php?logout=1" class="logout"><i class="fas fa-sign-out-alt"></i> <span>Logout</span></a></li>
            </ul>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            <div class="header">
                <h2>Dashboard Admin</h2>
                <div class="user-info">
                    <i class="fas fa-user-circle fa-2x"></i>
                    <div>
                        <h4><?= htmlspecialchars($_SESSION['admin_username']); ?></h4>
                        <p>Administrator</p>
                    </div>
                </div>
            </div>

            <?php if (isset($success_message)): ?>
                <div class="alert success">
                    <i class="fas fa-check-circle"></i> <?= $success_message; ?>
                </div>
            <?php endif; ?>
            <?php if (isset($error_message)): ?>
                <div class="alert error">
                    <i class="fas fa-exclamation-circle"></i> <?= $error_message; ?>
                </div>
            <?php endif; ?>

            <!-- Stats Cards -->
            <div class="stats">
                <div class="stat-card stat-1">
                    <div class="stat-icon"><i class="fas fa-briefcase"></i></div>
                    <div class="stat-text">
                        <h3><?= count($active_jobs); ?></h3>
                        <p>Lowongan Aktif</p>
                    </div>
                </div>
                <div class="stat-card stat-2">
                    <div class="stat-icon"><i class="fas fa-building"></i></div>
                    <div class="stat-text">
                        <h3>
                        <?php 
                            $companies = array_unique(array_column($active_jobs, 'perusahaan'));
                            echo count($companies);
                        ?>
                        </h3>
                        <p>Perusahaan Terdaftar</p>
                    </div>
                </div>
                <div class="stat-card stat-3">
                    <div class="stat-icon"><i class="fas fa-clock"></i></div>
                    <div class="stat-text">
                        <h3><?= count($pending_jobs); ?></h3>
                        <p>Pengajuan Menunggu</p>
                    </div>
                </div>
            </div>

            <!-- Pengajuan Lowongan Baru -->
            <div class="panel" id="pending">
                <div class="panel-header"><h3>Pengajuan Lowongan Baru</h3></div>
                <div class="panel-body">
                <?php if (empty($pending_jobs)): ?>
                    <div class="empty-state">
                        <i class="fas fa-check-circle"></i>
                        <p>Tidak ada pengajuan lowongan baru</p>
                    </div>
                <?php else: ?>
                    <table class="table">
                        <thead>
                        <tr>
                            <th>Posisi</th>
                            <th>Perusahaan</th>
                            <th>Lokasi</th>
                            <th>Email Kontak</th>
                            <th>Tanggal Ajuan</th>
                            <th>Aksi</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($pending_jobs as $job): ?>
                            <tr>
                                <td><?= htmlspecialchars($job['judul']); ?></td>
                                <td><?= htmlspecialchars($job['perusahaan']); ?></td>
                                <td><?= htmlspecialchars($job['lokasi']); ?></td>
                                <td><?= htmlspecialchars($job['contact_email']); ?></td>
                                <td><?= date('d M Y', strtotime($job['tanggal_post'])); ?></td>
                                <td>
                                    <form method="post" style="display:inline;">
                                        <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']); ?>">
                                        <input type="hidden" name="action" value="approve_job">
                                        <input type="hidden" name="job_id" value="<?= (int)$job['id']; ?>">
                                        <button type="submit" class="action-btn"><i class="fas fa-check"></i> Setujui</button>
                                    </form>
                                    <form method="post" style="display:inline;">
                                        <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']); ?>">
                                        <input type="hidden" name="action" value="reject_job">
                                        <input type="hidden" name="job_id" value="<?= (int)$job['id']; ?>">
                                        <button type="submit" class="action-btn delete"><i class="fas fa-times"></i> Tolak</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
                </div>
            </div>

            <!-- Lowongan Aktif -->
            <div class="panel" id="jobs">
                <div class="panel-header"><h3>Lowongan Aktif</h3></div>
                <div class="panel-body">
                <?php if (empty($active_jobs)): ?>
                    <div class="empty-state">
                        <i class="fas fa-briefcase"></i>
                        <p>Belum ada lowongan yang aktif</p>
                    </div>
                <?php else: ?>
                    <table class="table">
                        <thead>
                        <tr>
                            <th>Posisi</th>
                            <th>Perusahaan</th>
                            <th>Lokasi</th>
                            <th>Tanggal Posting</th>
                            <th>Tanggal Berakhir</th>
                            <th>Aksi</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($active_jobs as $job): ?>
                            <tr>
                                <td><?= htmlspecialchars($job['judul']); ?></td>
                                <td><?= htmlspecialchars($job['perusahaan']); ?></td>
                                <td><?= htmlspecialchars($job['lokasi']); ?></td>
                                <td><?= date('d M Y', strtotime($job['tanggal_post'])); ?></td>
                                <td><?= date('d M Y', strtotime($job['tanggal_akhir'])); ?></td>
                                <td>
                                    <form method="post" style="display:inline;">
                                        <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']); ?>">
                                        <input type="hidden" name="action" value="delete_job">
                                        <input type="hidden" name="job_id" value="<?= (int)$job['id']; ?>">
                                        <button type="submit" class="action-btn delete"><i class="fas fa-trash"></i> Hapus</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
                </div>
            </div>

            <!-- Form Tambah Lowongan -->
            <div class="panel" id="add-job">
                <div class="panel-header"><h3>Ajukan Lowongan Baru</h3></div>
                <div class="panel-body">
                    <form method="post">
                        <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']); ?>">
                        <input type="hidden" name="action" value="add_job">
                        <div class="form-row">
                            <div class="form-group">
                                <label for="judul">Posisi Pekerjaan *</label>
                                <input type="text" id="judul" name="judul" class="form-control" required placeholder="Contoh: Frontend Developer">
                            </div>
                            <div class="form-group">
                                <label for="perusahaan">Perusahaan *</label>
                                <input type="text" id="perusahaan" name="perusahaan" class="form-control" required placeholder="Nama perusahaan">
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label for="lokasi">Lokasi *</label>
                                <input type="text" id="lokasi" name="lokasi" class="form-control" required placeholder="Kota, Provinsi">
                            </div>
                            <div class="form-group">
                                <label for="id_kategori">Kategori *</label>
                                <select id="id_kategori" name="id_kategori" class="form-control" required>
                                    <option value="">Pilih Kategori</option>
                                    <?php foreach ($kategori as $kat): ?>
                                        <option value="<?= (int)$kat['id']; ?>"><?= htmlspecialchars($kat['nama_kategori']); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label for="tanggal_akhir">Tanggal Berakhir *</label>
                                <input type="date" id="tanggal_akhir" name="tanggal_akhir" class="form-control" required>
                            </div>
                            <div class="form-group">
                                <label for="contact_email">Email Kontak *</label>
                                <input type="email" id="contact_email" name="contact_email" class="form-control" required placeholder="email@perusahaan.com">
                            </div>
                        </div>

                        <div class="form-group">
                            <label for="deskripsi">Deskripsi Pekerjaan *</label>
                            <textarea id="deskripsi" name="deskripsi" class="form-control" rows="5" required placeholder="Deskripsikan pekerjaan secara detail"></textarea>
                        </div>

                        <div class="form-footer">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-paper-plane"></i> Ajukan Lowongan
                            </button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Akun & Password -->
            <div class="panel" id="account">
                <div class="panel-header"><h3>Akun & Password</h3></div>
                <div class="panel-body">
                    <form method="post" autocomplete="off">
                        <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']); ?>">
                        <input type="hidden" name="action" value="change_password">
                        <div class="form-row">
                            <div class="form-group">
                                <label for="current_password">Password Saat Ini</label>
                                <input type="password" id="current_password" name="current_password" class="form-control" required autocomplete="current-password">
                            </div>
                            <div class="form-group">
                                <label for="new_password">Password Baru (min 8)</label>
                                <input type="password" id="new_password" name="new_password" class="form-control" minlength="8" required autocomplete="new-password">
                            </div>
                        </div>
                        <div class="form-row">
                            <div class="form-group">
                                <label for="confirm_password">Ulangi Password Baru</label>
                                <input type="password" id="confirm_password" name="confirm_password" class="form-control" minlength="8" required autocomplete="new-password">
                            </div>
                        </div>
                        <div class="form-footer">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-key"></i> Ganti Password
                            </button>
                        </div>
                    </form>
                    <p class="footer-powered" style="margin-top:12px;color:#94a3b8">
                        Tips: gunakan password unik 12+ karakter.
                    </p>
                </div>
            </div>

            <footer class="footer-powered">Powered by <strong>UniverseRIA</strong></footer>
        </div>
    </div>
<?php endif; ?>

<script>
// === Navigasi sidebar ===
document.querySelectorAll('.nav-links a:not(.logout)').forEach(link => {
  link.addEventListener('click', function(e) {
    const href = this.getAttribute('href') || '';
    if (!href.startsWith('#')) return;
    e.preventDefault();
    document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
    this.classList.add('active');
    const el = document.querySelector(href);
    if (el) el.scrollIntoView({ behavior: 'smooth' });
  });
});

// === Konfirmasi sebelum hapus ===
document.querySelectorAll('form').forEach(form => {
  const act = form.querySelector('input[name="action"]');
  if (act && act.value === 'delete_job') {
    form.addEventListener('submit', function(e) {
      if (!confirm('Apakah Anda yakin ingin menghapus lowongan ini?')) {
        e.preventDefault();
      }
    });
  }
});

// === Tanggal minimal hari ini ===
const tglAkhir = document.getElementById('tanggal_akhir');
if (tglAkhir) {
  const today = new Date().toISOString().split('T')[0];
  tglAkhir.min = today;
}
</script>
</body>
</html>
