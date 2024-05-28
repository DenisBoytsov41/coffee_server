const validatePassword = (password) => {
    const passwordRegex = /^(?=.*\d)(?=.*[a-zа-я])(?=.*[A-ZА-Я])(?=.*\W).{8,}$/;
  
    if (!password) {
      return { success: false, errors: ['Пароль не может быть пустым'] };
    }
  
    if (!passwordRegex.test(password)) {
      return { success: false, errors: ['Пароль должен содержать не менее 8 символов и включать в себя хотя бы одну заглавную букву, одну строчную букву, одну цифру и один символ'] };
    }
  
    return { success: true, errors: [] };
  };
  
  module.exports = { validatePassword };
  