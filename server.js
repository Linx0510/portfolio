import express from 'express';
import session from 'express-session';
import bodyParser from 'body-parser';
import { Sequelize, DataTypes } from 'sequelize';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import expressLayouts from 'express-ejs-layouts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Используем SQLite файл вместо памяти для сохранения данных
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: path.join(__dirname, 'database.sqlite'),
    logging: false
});

try {
    await sequelize.authenticate();
    console.log('Соединение с БД установлено');
} catch (e) {
    console.log('Ошибка подключения к БД:', e);
    process.exit(1);
}

// Определение моделей
const Role = sequelize.define('Role', {
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
    },
    name: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    }
});

const User = sequelize.define('User', {
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
    },
    name: {
        type: DataTypes.STRING(100),
        allowNull: false,
        validate: {
            len: {
                args: [2, 100],
                msg: 'Имя должно содержать от 2 до 100 символов'
            },
            notEmpty: {
                msg: 'Имя не может быть пустым'
            }
        }
    },
    email: {
        type: DataTypes.STRING(255),
        allowNull: false,
        unique: {
            name: 'Ошибка',
            msg: 'Пользователь с таким email уже существует'
        },
        validate: {
            isEmail: {
                msg: 'Некорректный формат email'
            },
            notEmpty: {
                msg: 'Email не может быть пустым'
            }
        }
    },
    password: {
        type: DataTypes.STRING(255),
        allowNull: false,
        validate: {
            len: {
                args: [8, 255],
                msg: 'Пароль должен содержать минимум 8 символов'
            }
        }
    },
    roleId: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 2,
        validate: {
            isInt: true,
            min: 1
        }
    },
    isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true,
        allowNull: false
    },
    emailVerified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        allowNull: false
    }
}, {
    timestamps: true,
    paranoid: true,
    indexes: [
        { fields: ['email'] },
        { fields: ['roleId'] },
        { fields: ['isActive'] }
    ],
    defaultScope: {
        attributes: { exclude: ['password'] }
    },
    scopes: {
        withPassword: {
            attributes: { include: ['password'] }
        },
        active: {
            where: { isActive: true }
        }
    }
});

Role.hasMany(User, { foreignKey: "roleId" });
User.belongsTo(Role, { foreignKey: 'roleId' });

async function initializeRolesAndAdmin() {
    try {
        await sequelize.sync({ force: false });
        
        const roles = ['Администратор', 'Пользователь'];
        for (const roleName of roles) {
            await Role.findOrCreate({
                where: { name: roleName },
                defaults: { name: roleName }
            });
        }
        
        // Находим обе роли
        const adminRole = await Role.findOne({ where: { name: 'Администратор' } });
        const userRole = await Role.findOne({ where: { name: 'Пользователь' } });
        
        // Проверяем существование админа
        const existingAdmin = await User.findOne({ where: { email: 'admin@example.com' } });
        
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await User.create({
                name: 'Администратор',
                email: 'admin@example.com',
                password: hashedPassword,
                roleId: adminRole.id
            });
            console.log('Администратор создан: email - admin@example.com, пароль - admin123');
        }
        
        console.log('База данных инициализирована');
    } catch (error) {
        console.error('Ошибка инициализации БД:', error);
    }
}

const app = express();
const port = 5000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(
    session({
        secret: 'secret-key-linx-2024',
        resave: false,
        saveUninitialized: false,
        cookie: { 
            secure: false,
            maxAge: 24 * 60 * 60 * 1000 // 24 часа
        }
    })
);

// Статические файлы
app.use(express.static(path.join(__dirname, 'public')));

// EJS настройки с поддержкой layouts
app.use(expressLayouts);
app.set('layout', './layout');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware для передачи данных пользователя в шаблоны
app.use((req, res, next) => {
    if (req.session.user) {
        // Добавляем инициалы для аватарки
        const user = req.session.user;
        user.initials = user.name ? user.name.charAt(0).toUpperCase() : 'Л';
        res.locals.user = user;
    } else {
        res.locals.user = null;
    }
    next();
});

// Функции middleware
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
}

function hasRole(roleName) {
    return async (req, res, next) => {
        if (req.session.user) {
            try {
                const user = await User.findByPk(req.session.user.id, { include: Role });
                if (user && user.Role.name === roleName) {
                    next();
                } else {
                    res.status(403).send('Доступ запрещён');
                }
            } catch (error) {
                console.error('Ошибка проверки роли:', error);
                res.redirect('/login');
            }
        } else {
            res.redirect('/login');
        }
    };
}

// Маршруты
app.get('/', (req, res) => {
    if (req.session.user) {
        // Авторизованные пользователи идут в профиль
        res.redirect('/profile');
    } else {
        // Неавторизованные идут на страницу входа
        res.redirect('/login');
    }
});

// Основные страницы для навигации
app.get('/about', (req, res) => {
    res.render('about', { 
        title: 'Обо мне - LINX'
    });
});

app.get('/services', (req, res) => {
    res.render('services', { 
        title: 'Услуги - LINX'
    });
});

app.get('/works', (req, res) => {
    res.render('works', { 
        title: 'Работы - LINX'
    });
});

app.get('/contacts', (req, res) => {
    res.render('contacts', { 
        title: 'Контакты - LINX'
    });
});

app.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard', { 
        title: 'Панель управления - LINX'
    });
});

app.get('/register', (req, res) => {
    if (req.session.user) {
        return res.redirect('/profile');
    }
    res.render('register', { 
        title: 'Регистрация',
        errors: null,
        name: '',
        email: ''
    });
});

app.post('/register', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;
    
    // Валидация
    const errors = [];
    
    if (!name || !email || !password || !confirmPassword) {
        errors.push('Все поля обязательны для заполнения');
    }
    
    if (password !== confirmPassword) {
        errors.push('Пароли не совпадают');
    }
    
    if (password && password.length < 8) {
        errors.push('Пароль должен содержать минимум 8 символов');
    }
    
    if (name && (name.length < 2 || name.length > 100)) {
        errors.push('Имя должно содержать от 2 до 100 символов');
    }
    
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        errors.push('Некорректный формат email');
    }
    
    if (errors.length > 0) {
        return res.render('register', { 
            title: 'Регистрация',
            errors,
            name: name || '',
            email: email || ''
        });
    }
    
    try {
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.render('register', { 
                title: 'Регистрация',
                errors: ['Пользователь с таким email уже существует'],
                name,
                email
            });
        }

        // Автоматически находим роль "Пользователь"
        const userRole = await Role.findOne({ where: { name: 'Пользователь' } });
        
        if (!userRole) {
            throw new Error('Роль "Пользователь" не найдена');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await User.create({
            name,
            email,
            password: hashedPassword,
            roleId: userRole.id
        });

        res.redirect('/login?registered=true');
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        res.render('register', { 
            title: 'Регистрация',
            errors: ['Ошибка регистрации: ' + error.message],
            name: name || '',
            email: email || ''
        });
    }
});

app.get('/login', (req, res) => {
    if (req.session.user) {
        return res.redirect('/profile');
    }
    
    const registered = req.query.registered === 'true';
    res.render('login', { 
        title: 'Вход в систему',
        registered,
        error: null,
        email: ''
    });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const user = await User.scope('withPassword').findOne({ 
            where: { email },
            include: Role 
        });
        
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.user = { 
                id: user.id, 
                name: user.name,
                email: user.email,
                role: user.Role.name 
            };
            
            // После входа ВСЕ пользователи идут в свой профиль
            res.redirect('/profile');
        } else {
            res.render('login', { 
                title: 'Вход в систему',
                error: 'Неверный email или пароль',
                email: email || ''
            });
        }
    } catch (error) {
        console.error('Ошибка авторизации:', error);
        res.render('login', { 
            title: 'Вход в систему',
            error: 'Ошибка сервера при авторизации',
            email: email || ''
        });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Ошибка при выходе:', err);
        }
        res.redirect('/login?logout=success');
    });
});

// ПРОФИЛЬ - доступен всем авторизованным пользователям
app.get('/profile', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findByPk(req.session.user.id, { include: Role });
        
        res.render('profile', { 
            title: 'Профиль - ' + user.name,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.Role.name,
                createdAt: user.createdAt
            },
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Ошибка загрузки профиля:', error);
        res.redirect('/login');
    }
});

app.post('/profile/update', isAuthenticated, async (req, res) => {
    const { name } = req.body;
    const userId = req.session.user.id;
    
    try {
        const user = await User.findByPk(userId);
        
        if (!name || name.length < 2) {
            return res.redirect('/profile?error=Имя должно содержать минимум 2 символа');
        }
        
        user.name = name;
        await user.save();
        
        // Обновляем сессию
        req.session.user.name = name;
        
        res.redirect('/profile?success=Профиль обновлен');
        
    } catch (error) {
        console.error('Ошибка обновления:', error);
        res.redirect('/profile?error=Ошибка обновления профиля');
    }
});

// АДМИН-ПАНЕЛЬ - только для админов
app.get('/admin', isAuthenticated, hasRole('Админ'), async (req, res) => {
    try {
        const users = await User.findAll({ 
            include: Role,
            order: [['id', 'ASC']]
        });
        
        const formattedUsers = users.map(user => ({
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.Role.name,
            createdAt: user.createdAt.toLocaleDateString('ru-RU')
        }));
        
        res.render('admin', { 
            title: 'Админ-панель',
            users: formattedUsers 
        });
    } catch (error) {
        console.error('Ошибка загрузки админ-панели:', error);
        res.status(500).send('Ошибка загрузки админ-панели');
    }
});

// API эндпоинты (только для админов)
app.delete('/api/users/:id', isAuthenticated, hasRole('Админ'), async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const currentUser = req.session.user;
        
        if (userId === currentUser.id) {
            return res.status(400).json({ error: 'Нельзя удалить самого себя' });
        }
        
        const user = await User.findByPk(userId);
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        await user.destroy();
        res.json({ success: true });
    } catch (error) {
        console.error('Ошибка удаления пользователя:', error);
        res.status(500).json({ error: 'Ошибка удаления пользователя' });
    }
});

app.put('/api/users/:id/role', isAuthenticated, hasRole('Админ'), async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const { roleId } = req.body;
        
        const user = await User.findByPk(userId);
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        const role = await Role.findByPk(roleId);
        if (!role) {
            return res.status(400).json({ error: 'Роль не найдена' });
        }
        
        user.roleId = roleId;
        await user.save();
        
        res.json({ success: true, role: role.name });
    } catch (error) {
        console.error('Ошибка изменения роли:', error);
        res.status(500).json({ error: 'Ошибка изменения роли' });
    }
});

app.get('/api/roles', isAuthenticated, hasRole('Админ'), async (req, res) => {
    try {
        const roles = await Role.findAll();
        res.json(roles);
    } catch (error) {
        console.error('Ошибка получения ролей:', error);
        res.status(500).json({ error: 'Ошибка получения ролей' });
    }
});

// ВАЖНО: УБРАТЬ обработчики ошибок, которые используют несуществующие файлы
// Вместо них добавить простые обработчики в конце:

// Простой обработчик 404
app.use((req, res) => {
    res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>404 - Страница не найдена</title>
            <style>
                body { font-family: Arial; text-align: center; padding: 50px; }
                h1 { color: #dc2626; }
                a { color: #6d28d9; text-decoration: none; }
            </style>
        </head>
        <body>
            <h1>404 - Страница не найдена</h1>
            <p>Запрашиваемая страница не существует.</p>
            <p><a href="/">Вернуться на главную</a></p>
        </body>
        </html>
    `);
});

// Простой обработчик ошибок сервера
app.use((err, req, res, next) => {
    console.error('Ошибка сервера:', err);
    res.status(500).send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>500 - Ошибка сервера</title>
            <style>
                body { font-family: Arial; text-align: center; padding: 50px; }
                h1 { color: #dc2626; }
                a { color: #6d28d9; text-decoration: none; margin: 0 10px; }
                .error-details { 
                    background: #fee2e2; 
                    padding: 15px; 
                    margin: 20px auto; 
                    max-width: 600px; 
                    text-align: left; 
                    border-radius: 5px; 
                }
            </style>
        </head>
        <body>
            <h1>500 - Ошибка сервера</h1>
            <p>Произошла внутренняя ошибка сервера.</p>
            <div class="error-details">
                <strong>Ошибка:</strong> ${err.message || 'Неизвестная ошибка'}
            </div>
            <p>
                <a href="/">Главная</a>
                <a href="/login">Войти</a>
                <a href="javascript:location.reload()">Обновить</a>
            </p>
        </body>
        </html>
    `);
});

app.listen(port, async () => {
    await initializeRolesAndAdmin();
    console.log(`Сервер запущен: http://localhost:${port}/`);
    console.log('Данные для входа:');
    console.log('Администратор:');
    console.log('  Email: admin@example.com');
    console.log('  Пароль: admin123');
    console.log('\nДля регистрации нового пользователя перейдите на:');
    console.log('  http://localhost:5000/register');
});