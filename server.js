import express from 'express';
import session from 'express-session';
import bodyParser from 'body-parser';
import { Sequelize, DataTypes } from 'sequelize';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import expressLayouts from 'express-ejs-layouts';
import helmet from 'helmet';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

const Role = sequelize.define('Role', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: DataTypes.STRING, allowNull: false, unique: true }
});

const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: DataTypes.STRING(100), allowNull: false, validate: { len: [2, 100], notEmpty: true } },
  email: { type: DataTypes.STRING(255), allowNull: false, unique: true, validate: { isEmail: true, notEmpty: true } },
  password: { type: DataTypes.STRING(255), allowNull: false, validate: { len: [8, 255] } },
  roleId: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 2, validate: { isInt: true, min: 1 } },
  isActive: { type: DataTypes.BOOLEAN, defaultValue: true, allowNull: false },
  emailVerified: { type: DataTypes.BOOLEAN, defaultValue: false, allowNull: false }
}, {
  timestamps: true,
  paranoid: true,
  indexes: [
    { fields: ['email'] },
    { fields: ['roleId'] },
    { fields: ['isActive'] }
  ],
  defaultScope: { attributes: { exclude: ['password'] } },
  scopes: {
    withPassword: { attributes: { include: ['password'] } },
    active: { where: { isActive: true } },
    regularUsers: { where: { roleId: 2 } }
  }
});

const ProjectType = sequelize.define('ProjectType', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: DataTypes.STRING(100), allowNull: false, unique: true, validate: { notEmpty: true } },
  description: { type: DataTypes.TEXT, allowNull: true },
  stages: { type: DataTypes.JSON, allowNull: false, defaultValue: [] }
}, {
  timestamps: true
});

const Project = sequelize.define('Project', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: DataTypes.STRING(255), allowNull: false, validate: { notEmpty: true, len: [2, 255] } },
  description: { type: DataTypes.TEXT, allowNull: true },
  startDate: { type: DataTypes.DATE, allowNull: false, validate: { isDate: true } },
  deadline: { type: DataTypes.DATE, allowNull: false, validate: { isDate: true } },
  budget: { type: DataTypes.DECIMAL(10, 2), allowNull: false, validate: { isDecimal: true, min: 0 } },
  status: { type: DataTypes.ENUM('planned', 'in_progress', 'on_hold', 'completed', 'cancelled'), defaultValue: 'planned', allowNull: false },
  currentStage: { type: DataTypes.INTEGER, defaultValue: 0, allowNull: false },
  progress: { type: DataTypes.INTEGER, defaultValue: 0, validate: { min: 0, max: 100 } },
  notes: { type: DataTypes.TEXT, allowNull: true },
  userId: { type: DataTypes.INTEGER, allowNull: false, references: { model: 'Users', key: 'id' } },
  projectTypeId: { type: DataTypes.INTEGER, allowNull: false, references: { model: 'ProjectTypes', key: 'id' } }
}, {
  timestamps: true,
  indexes: [
    { fields: ['userId'] },
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

const ProjectStage = sequelize.define('ProjectStage', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: DataTypes.STRING(255), allowNull: false },
  description: { type: DataTypes.TEXT, allowNull: true },
  order: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  isCompleted: { type: DataTypes.BOOLEAN, defaultValue: false },
  completedAt: { type: DataTypes.DATE, allowNull: true }
}, {
  timestamps: true
});

Role.hasMany(User, { foreignKey: 'roleId' });
User.belongsTo(Role, { foreignKey: 'roleId' });

User.hasMany(Project, { foreignKey: 'userId', as: 'projects' });
Project.belongsTo(User, { foreignKey: 'userId', as: 'projectUser' });

ProjectType.hasMany(Project, { foreignKey: 'projectTypeId' });
Project.belongsTo(ProjectType, { foreignKey: 'projectTypeId' });

Project.hasMany(ProjectStage, { foreignKey: 'projectId' });
ProjectStage.belongsTo(Project, { foreignKey: 'projectId' });

async function initializeRolesTypesAndAdmin() {
  try {
    await sequelize.sync({ force: false });
    const roles = ['Админ', 'Пользователь'];
    for (const roleName of roles) {
      await Role.findOrCreate({ where: { name: roleName }, defaults: { name: roleName } });
    }

    const projectTypes = [
      { name: 'ДИЗАЙН-МАКЕТ', description: 'Создание дизайн-макета сайта или приложения', stages: ['Бриф и анализ', 'Мудборд', 'Прототип', 'Визуальный дизайн', 'Подготовка к передаче'] },
      { name: 'ВЕРСТКА', description: 'Верстка по готовому дизайну', stages: ['Анализ макета', 'Настройка окружения', 'Базовая верстка', 'Адаптивная верстка', 'Оптимизация и тестирование'] },
      { name: 'ПОЛНАЯ РАЗРАБОТКА', description: 'Полный цикл разработки проекта', stages: ['Анализ требований', 'Проектирование', 'Дизайн', 'Фронтенд разработка', 'Бэкенд разработка', 'Тестирование', 'Развертывание'] }
    ];
    for (const typeData of projectTypes) {
      await ProjectType.findOrCreate({ where: { name: typeData.name }, defaults: typeData });
    }

    const adminRole = await Role.findOne({ where: { name: 'Админ' } });
    const userRole = await Role.findOne({ where: { name: 'Пользователь' } });

    const existingAdmin = await User.findOne({ where: { email: 'Linx05@yandex.ru' } });
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash('Liana1234', 10);
      await User.create({
        name: 'Сисенова Лиана',
        email: 'Linx05@yandex.ru',
        password: hashedPassword,
        roleId: adminRole.id
      });
      console.log('Администратор создан');
    }

    const existingRegularUser = await User.findOne({ where: { email: 'user@example.com' } });
    if (!existingRegularUser) {
      const hashedPassword = await bcrypt.hash('user1234', 10);
      await User.create({
        name: 'Тестовый Пользователь',
        email: 'user@example.com',
        password: hashedPassword,
        roleId: userRole.id
      });
      console.log('Тестовый пользователь создан');
    }
    console.log('База данных инициализирована');
  } catch (error) {
    console.error('Ошибка инициализации БД:', error);
  }
}

const app = express();
const port = 5000;

app.use(helmet({
  contentSecurityPolicy: false,
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: 'secret-key-linx-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false,
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true
  }
}));

app.use(express.static(path.join(__dirname, 'public')));
app.use('/fonts', express.static(path.join(__dirname, 'public/fonts')));
app.use('/img', express.static(path.join(__dirname, 'public/img')));
app.use('/css', express.static(path.join(__dirname, 'public/css')));

app.use(expressLayouts);
app.set('layout', './layout');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use((req, res, next) => {
  if (req.session.user) {
    const user = req.session.user;
    user.initials = user.name ? user.name.charAt(0).toUpperCase() : 'Л';
    res.locals.user = user;
  } else {
    res.locals.user = null;
  }
  res.locals.path = req.path;
  next();
});

function isAuthenticated(req, res, next) {
  if (req.session.user) next();
  else res.redirect('/login');
}

function hasRole(roleName) {
  return async (req, res, next) => {
    if (req.session.user) {
      try {
        const user = await User.findByPk(req.session.user.id, { include: Role });
        if (user && user.Role.name === roleName) next();
        else res.status(403).send('Доступ запрещён');
      } catch (error) {
        console.error('Ошибка проверки роли:', error);
        res.redirect('/login');
      }
    } else res.redirect('/login');
  };
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/html/index.html'));
});

app.get('/project', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/html/project.html'));
});

app.get('/usluga', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/html/usluga.html'));
});

app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/profile');
  }
  const registered = req.query.registered === 'true';
  res.render('login', { 
    title: 'Вход в систему - LINX',
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
      
      if (user.Role.name === 'Админ') {
        res.redirect('/admin');
      } else {
        res.redirect('/user-dashboard');
      }
    } else {
      res.render('login', { 
        title: 'Вход в систему - LINX',
        error: 'Неверный email или пароль',
        email: email || ''
      });
    }
  } catch (error) {
    console.error('Ошибка авторизации:', error);
    res.render('login', { 
      title: 'Вход в систему - LINX',
      error: 'Ошибка сервера при авторизации',
      email: email || ''
    });
  }
});

app.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/profile');
  }
  res.render('register', { 
    title: 'Регистрация - LINX',
    errors: null,
    name: '',
    email: ''
  });
});

app.post('/register', async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;
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
      title: 'Регистрация - LINX',
      errors,
      name: name || '',
      email: email || ''
    });
  }
  
  try {
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.render('register', { 
        title: 'Регистрация - LINX',
        errors: ['Пользователь с таким email уже существует'],
        name,
        email
      });
    }

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
      title: 'Регистрация - LINX',
      errors: ['Ошибка регистрации: ' + error.message],
      name: name || '',
      email: email || ''
    });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Ошибка при выходе:', err);
    }
    res.redirect('/');
  });
});

app.get('/profile', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findByPk(req.session.user.id, { include: Role });
    
    let projectStats = {};
    if (user.Role.name === 'Админ') {
      const totalProjects = await Project.count();
      const activeProjects = await Project.count({ where: { status: 'in_progress' } });
      const completedProjects = await Project.count({ where: { status: 'completed' } });
      projectStats = { totalProjects, activeProjects, completedProjects };
    } else {
      const totalProjects = await Project.count({ where: { userId: user.id } });
      const activeProjects = await Project.count({ where: { userId: user.id, status: 'in_progress' } });
      const completedProjects = await Project.count({ where: { userId: user.id, status: 'completed' } });
      projectStats = { totalProjects, activeProjects, completedProjects };
    }
    
    res.render('profile', { 
      title: 'Профиль - ' + user.name + ' - LINX',
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
    
    req.session.user.name = name;
    
    res.redirect('/profile?success=Профиль обновлен');
  } catch (error) {
    console.error('Ошибка обновления:', error);
    res.redirect('/profile?error=Ошибка обновления профиля');
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
      name: user.name,
      email: user.email,
      role: user.Role.name,
      createdAt: user.createdAt
    }));
    
    const projects = await Project.findAll({
      include: [
        { 
          model: User, 
          as: 'projectUser',
          attributes: ['id', 'name', 'email'] 
        },
        { 
          model: ProjectType, 
          attributes: ['id', 'name'] 
        }
      ],
      order: [['createdAt', 'DESC']],
      limit: 5
    });
    
    const userRole = await Role.findOne({ where: { name: 'Пользователь' } });
    
    if (!userRole) {
      return res.status(500).send('Ошибка: роль "Пользователь" не найдена');
    }
    
    const regularUsers = await User.findAll({
      where: { 
        roleId: userRole.id,
        isActive: true
      },
      attributes: ['id', 'name', 'email'],
      order: [['name', 'ASC']]
    });
    
    const projectTypes = await ProjectType.findAll({
      order: [['name', 'ASC']]
    });
    
    const totalProjects = await Project.count();
    const activeProjects = await Project.count({ where: { status: 'in_progress' } });
    const completedProjects = await Project.count({ where: { status: 'completed' } });
    
    res.render('admin', { 
      title: 'Админ-панель - LINX',
      user: req.session.user,
      users: formattedUsers,
      projects: projects,
      regularUsers: regularUsers,
      projectTypes: projectTypes,
      totalProjects: totalProjects,
      activeProjects: activeProjects,
      completedProjects: completedProjects
    });
  } catch (error) {
    console.error('Ошибка загрузки админ-панели:', error);
    res.status(500).send(`Ошибка загрузки админ-панели: ${error.message}`);
  }
});

app.get('/user-dashboard', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findByPk(req.session.user.id, { include: Role });
    
    const totalProjects = await Project.count({ where: { userId: user.id } });
    const activeProjects = await Project.count({ 
      where: { 
        userId: user.id,
        status: 'in_progress' 
      } 
    });
    const completedProjects = await Project.count({ 
      where: { 
        userId: user.id,
        status: 'completed' 
      } 
    });
    
    const userProjects = await Project.findAll({
      where: { userId: user.id },
      include: [
        { 
          model: User, 
          as: 'projectUser',
          attributes: ['id', 'name', 'email'] 
        },
        { 
          model: ProjectType, 
          attributes: ['id', 'name'] 
        }
      ],
      order: [['createdAt', 'DESC']]
    });
    
    let totalProgress = 0;
    if (userProjects.length > 0) {
      const sumProgress = userProjects.reduce((sum, project) => sum + (project.progress || 0), 0);
      totalProgress = Math.round(sumProgress / userProjects.length);
    }
    
    res.render('user-dashboard', { 
      title: 'Панель управления - LINX',
      user: req.session.user,
      projects: userProjects,
      totalProjects: totalProjects,
      activeProjects: activeProjects,
      completedProjects: completedProjects,
      totalProgress: totalProgress
    });
  } catch (error) {
    console.error('Ошибка загрузки панели пользователя:', error);
    res.status(500).send(`Ошибка загрузки панели пользователя: ${error.message}`);
  }
});

app.get('/api/project/:id', isAuthenticated, async (req, res) => {
  try {
    const projectId = req.params.id;
    const user = await User.findByPk(req.session.user.id, { include: Role });
    
    const project = await Project.findByPk(projectId, {
      include: [
        { 
          model: User, 
          as: 'projectUser',
          attributes: ['id', 'name', 'email'] 
        },
        { 
          model: ProjectType, 
          attributes: ['id', 'name'] 
        }
      ]
    });
    
    if (!project) {
      return res.status(404).json({ error: 'Проект не найден' });
    }
    
    if (user.Role.name !== 'Админ' && project.userId !== user.id) {
      return res.status(403).json({ error: 'Доступ запрещен' });
    }
    
    res.json({
      id: project.id,
      name: project.name,
      description: project.description,
      startDate: project.startDate,
      deadline: project.deadline,
      budget: project.budget,
      status: project.status,
      progress: project.progress,
      notes: project.notes,
      userId: project.userId,
      projectTypeId: project.projectTypeId,
      createdAt: project.createdAt,
      updatedAt: project.updatedAt,
      user: project.projectUser
    });
  } catch (error) {
    console.error('Ошибка получения проекта:', error);
    res.status(500).json({ error: 'Ошибка получения проекта', message: error.message });
  }
});

app.get('/projects/:id/edit', isAuthenticated, hasRole('Админ'), async (req, res) => {
  try {
    const projectId = req.params.id;
    
    const project = await Project.findByPk(projectId, {
      include: [
        { 
          model: User, 
          as: 'projectUser',
          attributes: ['id', 'name', 'email'] 
        },
        { model: ProjectType }
      ]
    });
    
    if (!project) {
      return res.status(404).send('Проект не найден');
    }
    
    const userRole = await Role.findOne({ where: { name: 'Пользователь' } });
    const regularUsers = await User.findAll({
      where: { 
        roleId: userRole.id,
        isActive: true
      },
      attributes: ['id', 'name', 'email'],
      order: [['name', 'ASC']]
    });
    
    const projectTypes = await ProjectType.findAll({
      order: [['name', 'ASC']]
    });
    
    const formattedProject = {
      ...project.toJSON(),
      startDate: project.startDate ? project.startDate.toISOString().split('T')[0] : '',
      deadline: project.deadline ? project.deadline.toISOString().split('T')[0] : ''
    };
    
    res.render('edit-project', {
      title: `Редактировать проект: ${project.name} - LINX`,
      project: formattedProject,
      regularUsers,
      projectTypes
    });
  } catch (error) {
    console.error('Ошибка загрузки страницы редактирования:', error);
    res.redirect(`/projects/${req.params.id}?error=Ошибка загрузки`);
  }
});

app.post('/projects/:id/update', isAuthenticated, hasRole('Админ'), async (req, res) => {
  try {
    const projectId = req.params.id;
    const { 
      name, description, startDate, deadline, 
      budget, userId, projectTypeId, 
      status, progress, notes 
    } = req.body;
    
    const project = await Project.findByPk(projectId);
    if (!project) {
      return res.status(404).send('Проект не найден');
    }
    
    if (new Date(deadline) <= new Date(startDate)) {
      return res.redirect(`/projects/${projectId}/edit?error=Дедлайн должен быть позже даты начала`);
    }
    
    project.name = name;
    project.description = description;
    project.startDate = new Date(startDate);
    project.deadline = new Date(deadline);
    project.budget = parseFloat(budget);
    project.userId = parseInt(userId);
    project.projectTypeId = parseInt(projectTypeId);
    project.status = status;
    project.progress = parseInt(progress);
    project.notes = notes;
    
    await project.save();
    
    res.redirect(`/projects/${projectId}?success=Проект успешно обновлен`);
  } catch (error) {
    console.error('Ошибка обновления проекта:', error);
    res.redirect(`/projects/${req.params.id}/edit?error=${encodeURIComponent(error.message)}`);
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

app.get('/projects/:id', isAuthenticated, async (req, res) => {
  try {
    const projectId = req.params.id;
    const user = await User.findByPk(req.session.user.id, { include: Role });
    
    const project = await Project.findByPk(projectId, {
      include: [
        { 
          model: User, 
          as: 'projectUser',
          attributes: ['id', 'name', 'email'] 
        },
        { model: ProjectType, attributes: ['id', 'name', 'stages'] },
        { model: ProjectStage, order: [['order', 'ASC']] }
      ]
    });
    
    if (!project) {
      return res.status(404).send('Проект не найден');
    }
    
    if (user.Role.name !== 'Админ' && project.userId !== user.id) {
      return res.status(403).send('Доступ запрещен');
    }
    
    let regularUsers = [];
    if (user.Role.name === 'Админ') {
      const userRole = await Role.findOne({ where: { name: 'Пользователь' } });
      regularUsers = await User.findAll({
        where: { roleId: userRole.id },
        attributes: ['id', 'name', 'email'],
        order: [['name', 'ASC']]
      });
    }
    
    const projectTypes = await ProjectType.findAll();
    
    res.render('project-detail', {
      title: `${project.name} - LINX`,
      project,
      regularUsers,
      projectTypes,
      isAdmin: user.Role.name === 'Админ'
    });
  } catch (error) {
    console.error('Ошибка загрузки проекта:', error);
    res.redirect('/projects?error=Ошибка загрузки проекта');
  }
});

app.post('/projects', isAuthenticated, hasRole('Админ'), async (req, res) => {
  try {
    const { name, description, startDate, deadline, budget, userId, projectTypeId, notes } = req.body;
    const project = await Project.create({
      name,
      description,
      startDate: new Date(startDate),
      deadline: new Date(deadline),
      budget: parseFloat(budget),
      userId: parseInt(userId),
      projectTypeId: parseInt(projectTypeId),
      notes,
      status: 'planned'
    });
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
    res.redirect('/admin?success=Проект успешно создан');
  } catch (error) {
    console.error('Ошибка при создании проекта:', error);
    res.redirect('/admin?error=' + encodeURIComponent(error.message));
  }
});

app.post('/projects/:id', isAuthenticated, hasRole('Админ'), async (req, res) => {
  try {
    const projectId = req.params.id;
    const { name, description, startDate, deadline, budget, userId, projectTypeId, status, progress, notes } = req.body;
    
    const project = await Project.findByPk(projectId);
    if (!project) {
      return res.status(404).send('Проект не найден');
    }
    
    project.name = name;
    project.description = description;
    project.startDate = new Date(startDate);
    project.deadline = new Date(deadline);
    project.budget = parseFloat(budget);
    project.userId = parseInt(userId);
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

app.get('/api/regular-users', isAuthenticated, async (req, res) => {
  try {
    const userRole = await Role.findOne({ where: { name: 'Пользователь' } });
    
    if (!userRole) {
      return res.json([]);
    }
    
    const regularUsers = await User.findAll({
      where: { 
        roleId: userRole.id,
        isActive: true
      },
      attributes: ['id', 'name', 'email'],
      order: [['name', 'ASC']]
    });
    
    res.json(regularUsers);
  } catch (error) {
    console.error('Ошибка загрузки пользователей:', error);
    res.status(500).json({ 
      error: 'Ошибка загрузки пользователей',
      message: error.message 
    });
  }
});

app.get('/api/project-types', isAuthenticated, async (req, res) => {
  try {
    const projectTypes = await ProjectType.findAll({
      order: [['name', 'ASC']]
    });
    
    res.json(projectTypes);
  } catch (error) {
    console.error('Ошибка загрузки типов проектов:', error);
    res.status(500).json({ 
      error: 'Ошибка загрузки типов проектов',
      message: error.message 
    });
  }
});

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

app.get('/api/admin/regular-users', isAuthenticated, hasRole('Админ'), async (req, res) => {
  try {
    const userRole = await Role.findOne({ where: { name: 'Пользователь' } });
    
    if (!userRole) {
      return res.json([]);
    }
    
    const regularUsers = await User.findAll({
      where: { 
        roleId: userRole.id,
        isActive: true
      },
      attributes: ['id', 'name', 'email'],
      order: [['name', 'ASC']]
    });
    
    res.json(regularUsers);
  } catch (error) {
    console.error('Ошибка загрузки пользователей:', error);
    res.status(500).json({ 
      error: 'Ошибка загрузки пользователей',
      message: error.message 
    });
  }
});

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

app.get('/api/users/:id', isAuthenticated, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const user = await User.findByPk(userId, {
      include: Role,
      attributes: ['id', 'name', 'email', 'createdAt']
    });
    
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.Role.name,
      createdAt: user.createdAt
    });
  } catch (error) {
    console.error('Ошибка получения пользователя:', error);
    res.status(500).json({ error: 'Ошибка получения пользователя' });
  }
});

app.put('/api/projects/:id/edit', isAuthenticated, hasRole('Админ'), async (req, res) => {
  try {
    const projectId = req.params.id;
    const { name, description, startDate, deadline, budget, userId, projectTypeId, status, progress, notes } = req.body;
    
    const project = await Project.findByPk(projectId);
    if (!project) {
      return res.status(404).json({ error: 'Проект не найден' });
    }
    
    if (new Date(deadline) <= new Date(startDate)) {
      return res.status(400).json({ error: 'Дедлайн должен быть позже даты начала' });
    }
    
    project.name = name;
    project.description = description;
    project.startDate = new Date(startDate);
    project.deadline = new Date(deadline);
    project.budget = parseFloat(budget);
    project.userId = parseInt(userId);
    project.projectTypeId = parseInt(projectTypeId);
    project.status = status;
    project.progress = parseInt(progress);
    project.notes = notes;
    
    await project.save();
    
    res.json({ 
      success: true, 
      message: 'Проект успешно обновлен',
      project: {
        id: project.id,
        name: project.name,
        status: project.status,
        progress: project.progress
      }
    });
  } catch (error) {
    console.error('Ошибка обновления проекта:', error);
    res.status(500).json({ 
      error: 'Ошибка обновления проекта', 
      message: error.message 
    });
  }
});

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

app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findByPk(req.session.user.id, { include: Role });
    
    if (user.Role.name === 'Админ') {
      res.redirect('/admin');
    } else {
      res.redirect('/user-dashboard');
    }
  } catch (error) {
    console.error('Ошибка при определении роли:', error);
    res.redirect('/profile');
  }
});

app.listen(port, async () => {
  await initializeRolesTypesAndAdmin();
  console.log(`Сервер запущен: http://localhost:${port}/`);
  console.log('Данные для входа:');
  console.log('Администратор:');
  console.log('  Email: Linx05@yandex.ru');
  console.log('  Пароль: Liana1234');
  console.log('Тестовый пользователь (роль "Пользователь"):');
  console.log('  Email: user@example.com');
  console.log('  Пароль: user1234');
});