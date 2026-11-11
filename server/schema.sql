-- База ресторана «Тумар» (Cloudflare D1 = SQLite)
-- Выполните этот файл один раз в консоли базы D1 (вкладка Console → вставить → Execute).

-- Заявки на банкеты и столики
CREATE TABLE IF NOT EXISTS bookings (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at     TEXT    NOT NULL DEFAULT (datetime('now', '+5 hours')), -- время Казахстана
  kind           TEXT    NOT NULL DEFAULT 'banquet', -- banquet (банкет/той — занимает день) | table (столик)
  event_date     TEXT    NOT NULL,                   -- ГГГГ-ММ-ДД
  event_time     TEXT,                               -- ЧЧ:ММ
  guests         INTEGER NOT NULL,
  event_type     TEXT,                               -- свадьба, юбилей, беташар…
  name           TEXT    NOT NULL,
  phone          TEXT    NOT NULL,
  comment        TEXT,
  preorder       TEXT,                               -- блюда, которые гость выбрал на сайте
  preorder_total INTEGER,                            -- сумма по ценам меню, ₸
  source         TEXT    NOT NULL DEFAULT 'site',    -- site | admin
  status         TEXT    NOT NULL DEFAULT 'new',     -- new | confirmed | cancelled
  admin_note     TEXT,
  updated_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_bookings_date   ON bookings(event_date);
CREATE INDEX IF NOT EXISTS idx_bookings_status ON bookings(status);
CREATE INDEX IF NOT EXISTS idx_bookings_phone  ON bookings(phone, created_at);

-- Даты, которые администратор закрыл вручную (своё мероприятие, бронь по телефону, выходной)
CREATE TABLE IF NOT EXISTS blocked_dates (
  date        TEXT PRIMARY KEY,
  reason      TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now', '+5 hours'))
);

-- Настройки сайта из админки: меню с ценами, объявление
CREATE TABLE IF NOT EXISTS settings (
  key         TEXT PRIMARY KEY,
  value       TEXT NOT NULL,
  updated_at  TEXT NOT NULL DEFAULT (datetime('now', '+5 hours'))
);
