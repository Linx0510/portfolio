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

const sequelize = new Sequelize('sqlite::memory:');
try {
    await sequelize.authenticate();
    console.log('Соединение с БД есть');
} catch (e) {
    console.log('Соединения с БД нету', e);
}

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
    login: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    roleId: {
        type: DataTypes.INTEGER,
        references: {
            model: Role,
            key: 'id',
        },
        allowNull: false,
        defaultValue: 2
    }
});

Role.hasMany(User, { foreignKey: "roleId" });
User.belongsTo(Role, { foreignKey: 'roleId' });

async function initializeRolesAndAdmin() {
    try {
        await sequelize.sync({ force: false });
        
        const roles = ['Админ', 'Пользователь'];
        for (const roleName of roles) {
            await Role.findOrCreate({
                where: { name: roleName },
                defaults: { name: roleName }
            });
        }
        
        const adminRole = await Role.findOne({ where: { name: 'Админ' } });
        const existingAdmin = await User.findOne({ where: { login: 'admin' } });
        
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await User.create({
                login: 'admin',
                password: hashedPassword,
                roleId: adminRole.id
            });
            console.log('Администратор создан: логин - admin, пароль - admin123');
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
        secret: 'secret-key',
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false }
    })
);

// Статические файлы
app.use(express.static(path.join(__dirname, 'public')));
app.use('/css', express.static(path.join(__dirname, 'public', 'css')));

// EJS настройки с поддержкой layouts
app.use(expressLayouts);
app.set('layout', './layout');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

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
            const user = await User.findByPk(req.session.user.id, { include: Role });
            if (user && user.Role.name === roleName) {
                next();
            } else {
                res.status(403).send('Доступ запрещён');
            }
        } else {
            res.redirect('/login');
        }
    };
}

// Маршруты
app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/register', (req, res) => {
    res.render('register', { 
        title: 'Регистрация',
        cssFile: 'register.css',
        layout: './layout'
    });
});

app.post('/register', async (req, res) => {
    const { login, password } = req.body;
    
    if (!login || !password) {
        return res.status(400).render('register', { 
            title: 'Регистрация',
            cssFile: 'register.css',
            layout: './layout',
            error: 'Заполните все поля' 
        });
    }
    
    try {
        const existingUser = await User.findOne({ where: { login } });
        if (existingUser) {
            return res.status(400).render('register', { 
                title: 'Регистрация',
                cssFile: 'register.css',
                layout: './layout',
                error: 'Пользователь с таким логином уже существует' 
            });
        }

        const userRole = await Role.findOne({ where: { name: 'Пользователь' } });
        const hashedPassword = await bcrypt.hash(password, 10);

        await User.create({
            login,
            password: hashedPassword,
            roleId: userRole.id
        });

        res.redirect('/login?registered=true');
    } catch (error) {
        res.status(400).render('register', { 
            title: 'Регистрация',
            cssFile: 'register.css',
            layout: './layout',
            error: 'Ошибка регистрации: ' + error.message 
        });
    }
});

app.get('/login', (req, res) => {
    const registered = req.query.registered === 'true';
    res.render('login', { 
        title: 'Вход в систему',
        cssFile: 'login.css',
        layout: './layout',
        registered 
    });
});

app.post('/login', async (req, res) => {
    const { login, password } = req.body;
    
    try {
        const user = await User.findOne({ 
            where: { login }, 
            include: Role 
        });
        
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.user = { 
                id: user.id, 
                login: user.login, 
                role: user.Role.name 
            };
            
            if (user.Role.name === 'Админ') {
                res.redirect('/admin');
            } else {
                res.redirect('/profile');
            }
        } else {
            res.status(401).render('login', { 
                title: 'Вход в систему',
                cssFile: 'login.css',
                layout: './layout',
                error: 'Неверный логин или пароль' 
            });
        }
    } catch (error) {
        res.status(500).render('login', { 
            title: 'Вход в систему',
            cssFile: 'login.css',
            layout: './layout',
            error: 'Ошибка сервера: ' + error.message 
        });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/profile', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findByPk(req.session.user.id, { include: Role });
        res.render('profile', { 
            title: 'Профиль пользователя',
            cssFile: 'profile.css',
            layout: './layout',
            user: {
                id: user.id,
                login: user.login,
                role: user.Role.name
            }
        });
    } catch (error) {
        res.status(500).send('Ошибка загрузки профиля');
    }
});

app.get('/admin', isAuthenticated, hasRole('Админ'), async (req, res) => {
    try {
        const users = await User.findAll({ 
            include: Role,
            order: [['id', 'ASC']]
        });
        
        const formattedUsers = users.map(user => ({
            id: user.id,
            login: user.login,
            role: user.Role.name,
            createdAt: user.createdAt
        }));
        
        res.render('admin', { 
            title: 'Админ-панель',
            cssFile: 'admin.css',
            layout: './layout',
            users: formattedUsers 
        });
    } catch (error) {
        res.status(500).send('Ошибка загрузки админ-панели');
    }
});

// API эндпоинты
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
        res.status(500).json({ error: 'Ошибка изменения роли' });
    }
});

app.get('/api/roles', isAuthenticated, hasRole('Админ'), async (req, res) => {
    try {
        const roles = await Role.findAll();
        res.json(roles);
    } catch (error) {
        res.status(500).json({ error: 'Ошибка получения ролей' });
    }
});

app.listen(port, async () => {
    await initializeRolesAndAdmin();
    console.log(`Сервер запущен: http://localhost:${port}/`);
    console.log('Данные администратора:');
    console.log('Логин: admin');
    console.log('Пароль: admin123');
});
