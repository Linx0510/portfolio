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

// Модель типа проекта
const ProjectType = sequelize.define('ProjectType', {
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
    },
    name: {
        type: DataTypes.STRING(100),
        allowNull: false,
        unique: true,
        validate: {
            notEmpty: {
                msg: 'Название типа не может быть пустым'
            }
        }
    },
    description: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    stages: {
        type: DataTypes.JSON, // JSON массив этапов для этого типа
        allowNull: false,
        defaultValue: []
    }
}, {
    timestamps: true
});

// Модель проекта
const Project = sequelize.define('Project', {
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
    },
    name: {
        type: DataTypes.STRING(255),
        allowNull: false,
        validate: {
            notEmpty: {
                msg: 'Название проекта не может быть пустым'
            },
            len: {
                args: [2, 255],
                msg: 'Название проекта должно содержать от 2 до 255 символов'
            }
        }
    },
    description: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    startDate: {
        type: DataTypes.DATE,
        allowNull: false,
        validate: {
            isDate: {
                msg: 'Дата начала должна быть корректной датой'
            }
        }
    },
    deadline: {
        type: DataTypes.DATE,
        allowNull: false,
        validate: {
            isDate: {
                msg: 'Дедлайн должен быть корректной датой'
            },
            isAfterStartDate(value) {
                if (value <= this.startDate) {
                    throw new Error('Дедлайн должен быть позже даты начала');
                }
            }
        }
    },
    budget: {
        type: DataTypes.DECIMAL(10, 2), // до 10 цифр, 2 после запятой
        allowNull: false,
        validate: {
            isDecimal: {
                msg: 'Бюджет должен быть числом'
            },
            min: {
                args: [0],
                msg: 'Бюджет не может быть отрицательным'
            }
        }
    },
    status: {
        type: DataTypes.ENUM('planned', 'in_progress', 'on_hold', 'completed', 'cancelled'),
        defaultValue: 'planned',
        allowNull: false
    },
    currentStage: {
        type: DataTypes.INTEGER, // индекс текущего этапа из stages в ProjectType
        defaultValue: 0,
        allowNull: false
    },
    progress: {
        type: DataTypes.INTEGER, // процент выполнения от 0 до 100
        defaultValue: 0,
        validate: {
            min: 0,
            max: 100
        }
    },
    notes: {
        type: DataTypes.TEXT,
        allowNull: true
    }
}, {
    timestamps: true,
    indexes: [
        { fields: ['clientId'] },
        { fields: ['projectTypeId'] },
        { fields: ['status'] },
        { fields: ['deadline'] }
    ],
    hooks: {
        beforeCreate: (project) => {
            if (project.deadline <= project.startDate) {
                throw new Error('Дедлайн должен быть позже даты начала');
            }
        },
        beforeUpdate: (project) => {
            if (project.changed('deadline') && project.deadline <= project.startDate) {
                throw new Error('Дедлайн должен быть позже даты начала');
            }
        }
    }
});

// Определение связей между моделями
Role.hasMany(User, { foreignKey: "roleId" });
User.belongsTo(Role, { foreignKey: 'roleId' });

// Клиент (User) может иметь много проектов
User.hasMany(Project, { foreignKey: 'clientId', as: 'clientProjects' });
Project.belongsTo(User, { foreignKey: 'clientId', as: 'client' });

// Тип проекта может использоваться в многих проектах
ProjectType.hasMany(Project, { foreignKey: 'projectTypeId' });
Project.belongsTo(ProjectType, { foreignKey: 'projectTypeId' });

// Модель этапа проекта (дополнительная модель для хранения этапов)
const ProjectStage = sequelize.define('ProjectStage', {
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
    },
    name: {
        type: DataTypes.STRING(255),
        allowNull: false
    },
    description: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    order: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0
    },
    isCompleted: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    },
    completedAt: {
        type: DataTypes.DATE,
        allowNull: true
    }
}, {
    timestamps: true
});

// Связь проекта с этапами
Project.hasMany(ProjectStage, { foreignKey: 'projectId' });
ProjectStage.belongsTo(Project, { foreignKey: 'projectId' });

async function initializeRolesTypesAndAdmin() {
    try {
        await sequelize.sync({ force: false });
        
        // Инициализация ролей
        const roles = ['Админ', 'Пользователь'];
        for (const roleName of roles) {
            await Role.findOrCreate({
                where: { name: roleName },
                defaults: { name: roleName }
            });
        }
        
        // Инициализация типов проектов
        const projectTypes = [
            {
                name: 'ДИЗАЙН-МАКЕТ',
                description: 'Создание дизайн-макета сайта или приложения',
                stages: ['Бриф и анализ', 'Мудборд', 'Прототип', 'Визуальный дизайн', 'Подготовка к передаче']
            },
            {
                name: 'ВЕРСТКА',
                description: 'Верстка по готовому дизайну',
                stages: ['Анализ макета', 'Настройка окружения', 'Базовая верстка', 'Адаптивная верстка', 'Оптимизация и тестирование']
            },
            {
                name: 'ПОЛНАЯ РАЗРАБОТКА',
                description: 'Полный цикл разработки проекта',
                stages: ['Анализ требований', 'Проектирование', 'Дизайн', 'Фронтенд разработка', 'Бэкенд разработка', 'Тестирование', 'Развертывание']
            }
        ];
        
        for (const typeData of projectTypes) {
            await ProjectType.findOrCreate({
                where: { name: typeData.name },
                defaults: typeData
            });
        }
        
        // Находим обе роли
        const adminRole = await Role.findOne({ where: { name: 'Админ' } });
        const userRole = await Role.findOne({ where: { name: 'Пользователь' } });
        
        // Проверяем существование админа
        const existingAdmin = await User.findOne({ where: { email: 'Linx05@yandex.ru' } });
        
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash('Liana1234', 10);
            await User.create({
                name: 'Сисенова Лиана',
                email: 'Linx05@yandex.ru',
                password: hashedPassword,
                roleId: adminRole.id
            });
            console.log('Администратор создан: email - Linx05@yandex.ru, пароль - Liana1234');
        }
        
        // Создаем тестового клиента
        const existingClient = await User.findOne({ where: { email: 'client@example.com' } });
        
        if (!existingClient) {
            const hashedPassword = await bcrypt.hash('client123', 10);
            await User.create({
                name: 'Тестовый Клиент',
                email: 'client@example.com',
                password: hashedPassword,
                roleId: userRole.id
            });
            console.log('Тестовый клиент создан: email - client@example.com, пароль - client123');
        }
        
        console.log('База данных инициализирована');
        console.log('Типы проектов созданы:', projectTypes.map(t => t.name).join(', '));
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

// Маршруты для проектов
app.get('/projects', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findByPk(req.session.user.id, { include: Role });
        let projects;
        
        if (user.Role.name === 'Админ') {
            projects = await Project.findAll({
                include: [
                    { model: User, as: 'client', attributes: ['id', 'name', 'email'] },
                    { model: ProjectType, attributes: ['id', 'name'] }
                ],
                order: [['createdAt', 'DESC']]
            });
        } else {
            projects = await Project.findAll({
                where: { clientId: user.id },
                include: [
                    { model: User, as: 'client', attributes: ['id', 'name', 'email'] },
                    { model: ProjectType, attributes: ['id', 'name'] }
                ],
                order: [['createdAt', 'DESC']]
            });
        }
        
        res.render('projects', { 
            title: 'Проекты - LINX',
            projects,
            isAdmin: user.Role.name === 'Админ'
        });
    } catch (error) {
        console.error('Ошибка загрузки проектов:', error);
        res.redirect('/profile?error=Ошибка загрузки проектов');
    }
});

app.get('/projects/new', isAuthenticated, hasRole('Админ'), async (req, res) => {
    try {
        const clients = await User.findAll({
            where: { roleId: 2 }, // Только обычные пользователи (клиенты)
            attributes: ['id', 'name', 'email']
        });
        
        const projectTypes = await ProjectType.findAll();
        
        res.render('project-form', {
            title: 'Создать новый проект - LINX',
            project: null,
            clients,
            projectTypes,
            action: '/projects'
        });
    } catch (error) {
        console.error('Ошибка загрузки формы:', error);
        res.redirect('/projects?error=Ошибка загрузки формы');
    }
});

app.post('/projects', isAuthenticated, hasRole('Админ'), async (req, res) => {
    try {
        const { name, description, startDate, deadline, budget, clientId, projectTypeId, notes } = req.body;
        
        const project = await Project.create({
            name,
            description,
            startDate: new Date(startDate),
            deadline: new Date(deadline),
            budget: parseFloat(budget),
            clientId: parseInt(clientId),
            projectTypeId: parseInt(projectTypeId),
            notes,
            status: 'planned'
        });
        
        // Создаем этапы проекта на основе типа
        const projectType = await ProjectType.findByPk(projectTypeId);
        if (projectType && projectType.stages) {
            for (let i = 0; i < projectType.stages.length; i++) {
                await ProjectStage.create({
                    name: projectType.stages[i],
                    order: i,
                    projectId: project.id
                });
            }
        }
        
        res.redirect('/projects?success=Проект создан успешно');
    } catch (error) {
        console.error('Ошибка создания проекта:', error);
        res.redirect('/projects/new?error=' + encodeURIComponent(error.message));
    }
});

app.get('/projects/:id', isAuthenticated, async (req, res) => {
    try {
        const projectId = req.params.id;
        const user = await User.findByPk(req.session.user.id, { include: Role });
        
        const project = await Project.findByPk(projectId, {
            include: [
                { model: User, as: 'client', attributes: ['id', 'name', 'email'] },
                { model: ProjectType, attributes: ['id', 'name', 'stages'] },
                { model: ProjectStage, order: [['order', 'ASC']] }
            ]
        });
        
        if (!project) {
            return res.status(404).send('Проект не найден');
        }
        
        // Проверка доступа
        if (user.Role.name !== 'Админ' && project.clientId !== user.id) {
            return res.status(403).send('Доступ запрещен');
        }
        
        const clients = await User.findAll({
            where: { roleId: 2 },
            attributes: ['id', 'name', 'email']
        });
        
        const projectTypes = await ProjectType.findAll();
        
        res.render('project-detail', {
            title: `${project.name} - LINX`,
            project,
            clients,
            projectTypes,
            isAdmin: user.Role.name === 'Админ'
        });
    } catch (error) {
        console.error('Ошибка загрузки проекта:', error);
        res.redirect('/projects?error=Ошибка загрузки проекта');
    }
});

app.post('/projects/:id', isAuthenticated, hasRole('Админ'), async (req, res) => {
    try {
        const projectId = req.params.id;
        const { name, description, startDate, deadline, budget, clientId, projectTypeId, status, progress, notes } = req.body;
        
        const project = await Project.findByPk(projectId);
        if (!project) {
            return res.status(404).send('Проект не найден');
        }
        
        project.name = name;
        project.description = description;
        project.startDate = new Date(startDate);
        project.deadline = new Date(deadline);
        project.budget = parseFloat(budget);
        project.clientId = parseInt(clientId);
        project.projectTypeId = parseInt(projectTypeId);
        project.status = status;
        project.progress = parseInt(progress);
        project.notes = notes;
        
        await project.save();
        
        res.redirect(`/projects/${projectId}?success=Проект обновлен`);
    } catch (error) {
        console.error('Ошибка обновления проекта:', error);
        res.redirect(`/projects/${req.params.id}?error=${encodeURIComponent(error.message)}`);
    }
});

app.post('/projects/:id/stages/:stageId/complete', isAuthenticated, hasRole('Админ'), async (req, res) => {
    try {
        const { stageId } = req.params;
        
        const stage = await ProjectStage.findByPk(stageId);
        if (!stage) {
            return res.status(404).json({ error: 'Этап не найден' });
        }
        
        stage.isCompleted = true;
        stage.completedAt = new Date();
        await stage.save();
        
        // Пересчитываем прогресс проекта
        const project = await Project.findByPk(stage.projectId, {
            include: [ProjectStage]
        });
        
        const totalStages = project.ProjectStages.length;
        const completedStages = project.ProjectStages.filter(s => s.isCompleted).length;
        const progress = Math.round((completedStages / totalStages) * 100);
        
        project.progress = progress;
        project.currentStage = completedStages;
        
        if (progress === 100) {
            project.status = 'completed';
        } else if (progress > 0) {
            project.status = 'in_progress';
        }
        
        await project.save();
        
        res.json({ success: true, progress, currentStage: project.currentStage });
    } catch (error) {
        console.error('Ошибка завершения этапа:', error);
        res.status(500).json({ error: 'Ошибка завершения этапа' });
    }
});

app.delete('/projects/:id', isAuthenticated, hasRole('Админ'), async (req, res) => {
    try {
        const projectId = req.params.id;
        const project = await Project.findByPk(projectId);
        
        if (!project) {
            return res.status(404).json({ error: 'Проект не найден' });
        }
        
        await project.destroy();
        res.json({ success: true });
    } catch (error) {
        console.error('Ошибка удаления проекта:', error);
        res.status(500).json({ error: 'Ошибка удаления проекта' });
    }
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
        
        // Получаем статистику проектов для пользователя
        let projectStats = {};
        if (user.Role.name === 'Админ') {
            const totalProjects = await Project.count();
            const activeProjects = await Project.count({ where: { status: 'in_progress' } });
            const completedProjects = await Project.count({ where: { status: 'completed' } });
            projectStats = { totalProjects, activeProjects, completedProjects };
        } else {
            const totalProjects = await Project.count({ where: { clientId: user.id } });
            const activeProjects = await Project.count({ where: { clientId: user.id, status: 'in_progress' } });
            const completedProjects = await Project.count({ where: { clientId: user.id, status: 'completed' } });
            projectStats = { totalProjects, activeProjects, completedProjects };
        }
        
        res.render('profile', { 
            title: 'Профиль - ' + user.name,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.Role.name,
                createdAt: user.createdAt
            },
            projectStats,
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

// API для получения статистики проектов
app.get('/api/projects/stats', isAuthenticated, hasRole('Админ'), async (req, res) => {
    try {
        const totalProjects = await Project.count();
        const projectsByStatus = await Project.findAll({
            attributes: ['status', [sequelize.fn('COUNT', sequelize.col('status')), 'count']],
            group: ['status']
        });
        
        const projectsByType = await Project.findAll({
            attributes: [
                [sequelize.col('ProjectType.name'), 'type'],
                [sequelize.fn('COUNT', sequelize.col('Project.id')), 'count']
            ],
            include: [{ model: ProjectType, attributes: [] }],
            group: ['ProjectType.name']
        });
        
        const totalBudget = await Project.sum('budget');
        
        res.json({
            totalProjects,
            projectsByStatus,
            projectsByType,
            totalBudget
        });
    } catch (error) {
        console.error('Ошибка получения статистики:', error);
        res.status(500).json({ error: 'Ошибка получения статистики' });
    }
});

app.listen(port, async () => {
    await initializeRolesTypesAndAdmin();
    console.log(`Сервер запущен: http://localhost:${port}/`);
    console.log('Данные для входа:');
    console.log('Администратор:');
    console.log('  Email: Linx05@yandex.ru');
    console.log('  Пароль: Liana1234');
});