<?php
session_start();

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
    http_response_code(500);
    die("Database connection failed.");
}

function clean_input($s){ return htmlspecialchars(trim((string)$s), ENT_QUOTES, 'UTF-8'); }

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

function get_categories(PDO $pdo){
    return $pdo->query("SELECT id, nama_kategori FROM kategori ORDER BY nama_kategori ASC")->fetchAll();
}
function get_active_jobs(PDO $pdo, $q = '', $cat = null){
    $sql = "SELECT l.*, k.nama_kategori FROM lowongan l LEFT JOIN kategori k ON k.id = l.id_kategori WHERE l.status = 'active'";
    $params = [];
    if ($q !== '') {
        $sql .= " AND (l.judul LIKE :kw OR l.perusahaan LIKE :kw OR l.lokasi LIKE :kw)";
        $params[':kw'] = "%{$q}%";
    }
    if (!empty($cat) && ctype_digit((string)$cat)) {
        $sql .= " AND l.id_kategori = :cat";
        $params[':cat'] = (int)$cat;
    }
    $sql .= " ORDER BY l.tanggal_post DESC";
    $st = $pdo->prepare($sql);
    $st->execute($params);
    return $st->fetchAll();
}
function create_public_job(PDO $pdo, array $data){
    $sql = "INSERT INTO lowongan (id_kategori, judul, deskripsi, tanggal_post, tanggal_akhir, perusahaan, lokasi, status, contact_email)
            VALUES (:id_kategori, :judul, :deskripsi, CURDATE(), :tanggal_akhir, :perusahaan, :lokasi, 'pending', :contact_email)";
    $st = $pdo->prepare($sql);
    return $st->execute([
        ':id_kategori'   => (int)$data['id_kategori'],
        ':judul'         => $data['judul'],
        ':deskripsi'     => $data['deskripsi'],
        ':tanggal_akhir' => $data['tanggal_akhir'],
        ':perusahaan'    => $data['perusahaan'],
        ':lokasi'        => $data['lokasi'],
        ':contact_email' => $data['contact_email'],
    ]);
}

$success_message = $error_message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'public_add_job') {
    if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) {
        $error_message = "Sesi tidak valid. Silakan muat ulang halaman.";
    } else {
        $id_kategori   = clean_input($_POST['id_kategori'] ?? '');
        $judul         = clean_input($_POST['judul'] ?? '');
        $deskripsi     = clean_input($_POST['deskripsi'] ?? '');
        $tanggal_akhir = clean_input($_POST['tanggal_akhir'] ?? '');
        $perusahaan    = clean_input($_POST['perusahaan'] ?? '');
        $lokasi        = clean_input($_POST['lokasi'] ?? '');
        $email         = clean_input($_POST['contact_email'] ?? '');

        if ($judul === '' || $perusahaan === '' || $lokasi === '' || $tanggal_akhir === '' || $email === '' || $id_kategori === '') {
            $error_message = "Semua kolom bertanda * wajib diisi.";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error_message = "Format email tidak valid.";
        } else {
            $today = new DateTimeImmutable('today');
            $end   = DateTimeImmutable::createFromFormat('Y-m-d', $tanggal_akhir);
            if (!$end || $end < $today) {
                $error_message = "Tanggal berakhir minimal hari ini atau setelahnya.";
            } else {
                if (create_public_job($pdo, [
                    'id_kategori'   => $id_kategori,
                    'judul'         => $judul,
                    'deskripsi'     => $deskripsi,
                    'tanggal_akhir' => $tanggal_akhir,
                    'perusahaan'    => $perusahaan,
                    'lokasi'        => $lokasi,
                    'contact_email' => $email,
                ])) {
                    $success_message = "Terima kasih! Lowongan Anda terkirim dan menunggu persetujuan admin.";
                } else {
                    $error_message = "Gagal mengirim lowongan. Coba lagi.";
                }
            }
        }
    }
}

$q     = trim($_GET['q'] ?? '');
$cat   = $_GET['cat'] ?? '';
$cats  = get_categories($pdo);
$jobs  = get_active_jobs($pdo, $q, $cat);
?>
<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lowongan Kerja - UniverseRIA Job Board</title>
  <link rel="stylesheet" href="public.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>

<header class="topbar">
  <div class="wrap">
    <div class="brand"><i class="fas fa-briefcase"></i> <span>UniverseRIA Job Board</span></div>
    <nav class="nav">
      <a href="#jobs">Lowongan</a>
      <a href="#submit">Ajukan Lowongan</a>
    </nav>
  </div>
</header>

<section class="hero">
  <h1 class="title">Temukan Pekerjaan Terbaru</h1>
  <p class="muted">Cari posisi sesuai minatmu, atau ajukan lowongan untuk perusahaanmu.</p>
  <form class="searchbar" method="get" action="#jobs">
    <input class="form-control" type="text" name="q" placeholder="Cari judul / perusahaan / lokasi" value="<?= clean_input($q) ?>">
    <select class="form-control" name="cat">
      <option value="">Semua Kategori</option>
      <?php foreach ($cats as $c): ?>
        <option value="<?= (int)$c['id'] ?>" <?= ($cat!=='' && (int)$cat===(int)$c['id'])?'selected':'' ?>>
          <?= clean_input($c['nama_kategori']) ?>
        </option>
      <?php endforeach; ?>
    </select>
    <button class="btn btn-primary" type="submit"><i class="fas fa-search"></i> Cari</button>
  </form>
</section>

<section class="job-grid" id="jobs">
  <?php if (empty($jobs)): ?>
    <div class="empty-state">
      <i class="fas fa-briefcase"></i>
      <p>Tidak ada lowongan yang cocok.</p>
    </div>
  <?php else: ?>
    <?php foreach ($jobs as $job): ?>
      <article class="job-card">
        <h3 class="job-title"><?= clean_input($job['judul']) ?></h3>
        <div class="job-meta">
          <span><i class="fas fa-building"></i> <?= clean_input($job['perusahaan']) ?></span>
          <span><i class="fas fa-location-dot"></i> <?= clean_input($job['lokasi']) ?></span>
          <?php if (!empty($job['nama_kategori'])): ?>
            <span><i class="fas fa-tag"></i> <?= clean_input($job['nama_kategori']) ?></span>
          <?php endif; ?>
          <span><i class="fas fa-calendar"></i> Diposting: <?= date('d M Y', strtotime($job['tanggal_post'])) ?></span>
          <span><i class="fas fa-hourglass-end"></i> Berakhir: <?= date('d M Y', strtotime($job['tanggal_akhir'])) ?></span>
        </div>
        <?php if (!empty($job['deskripsi'])): ?>
          <p class="job-desc"><?= nl2br(clean_input(mb_strimwidth($job['deskripsi'],0,300,'…','UTF-8'))) ?></p>
        <?php endif; ?>
      </article>
    <?php endforeach; ?>
  <?php endif; ?>
</section>

<section class="section" id="submit">
  <h2>Ajukan Lowongan Baru</h2>
  <p class="muted">Isi formulir berikut. Lowongan akan tampil setelah disetujui admin.</p>

  <?php if ($success_message): ?>
    <div class="alert success"><i class="fas fa-check-circle"></i> <?= $success_message ?></div>
  <?php endif; ?>
  <?php if ($error_message): ?>
    <div class="alert error"><i class="fas fa-exclamation-circle"></i> <?= $error_message ?></div>
  <?php endif; ?>

  <form method="post">
    <input type="hidden" name="action" value="public_add_job">
    <input type="hidden" name="csrf" value="<?= $_SESSION['csrf'] ?>">
    <div class="form-row">
      <div class="form-group">
        <label for="judul">Posisi *</label>
        <input class="form-control" type="text" id="judul" name="judul" required>
      </div>
      <div class="form-group">
        <label for="perusahaan">Perusahaan *</label>
        <input class="form-control" type="text" id="perusahaan" name="perusahaan" required>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label for="lokasi">Lokasi *</label>
        <input class="form-control" type="text" id="lokasi" name="lokasi" required placeholder="Kota, Provinsi">
      </div>
      <div class="form-group">
        <label for="id_kategori">Kategori *</label>
        <select class="form-control" id="id_kategori" name="id_kategori" required>
          <option value="">Pilih Kategori</option>
          <?php foreach ($cats as $c): ?>
            <option value="<?= (int)$c['id'] ?>"><?= clean_input($c['nama_kategori']) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label for="tanggal_akhir">Tanggal Berakhir *</label>
        <input class="form-control" type="date" id="tanggal_akhir" name="tanggal_akhir" required>
      </div>
      <div class="form-group">
        <label for="contact_email">Email Kontak *</label>
        <input class="form-control" type="email" id="contact_email" name="contact_email" required placeholder="email@perusahaan.com">
      </div>
    </div>
    <div class="form-group">
      <label for="deskripsi">Deskripsi Pekerjaan *</label>
      <textarea class="form-control" id="deskripsi" name="deskripsi" rows="5" required></textarea>
    </div>
    <div class="form-footer">
      <button class="btn btn-primary" type="submit"><i class="fas fa-paper-plane"></i> Kirim Ajuan</button>
    </div>
  </form>
</section>

<footer class="footer-powered">Powered by <strong>UniverseRIA</strong></footer>

<script>
  const dateEl = document.getElementById('tanggal_akhir');
  if (dateEl) dateEl.min = new Date().toISOString().split('T')[0];
</script>
</body>
</html>
