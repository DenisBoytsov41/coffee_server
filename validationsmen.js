const validateSmen = (data) => {
  const { firstname, lastname, email, gender, phone } = data;
  const errors = [];
  console.log("Я в validateSmen");
  console.log(data);

  // Регулярное выражение для проверки имен и фамилий, включая двойные фамилии
  const nameRegex = /^[а-яА-Яa-zA-Z]+(?:[-\s][а-яА-Яa-zA-Z]+)*$/u;

  // Проверка имени
  if (firstname) {
    console.log(firstname);
    if (!nameRegex.test(firstname)) {
      errors.push('Недопустимое имя');
    } else if (firstname.length < 2) {
      console.log(firstname);
      errors.push('Имя должно быть не менее двух символов');
    }
  }

  // Проверка фамилии
  if (lastname) {
    console.log(lastname);
    if (!nameRegex.test(lastname)) {
      errors.push('Недопустимая фамилия');
    } else if (lastname.length < 2) {
      console.log(lastname);
      errors.push('Фамилия должна быть не менее двух символов');
    }
  }

  // Проверка email
  if (email) {
    console.log(email);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.log(email);
      errors.push('Недопустимый email');
    }
  }

  // Проверка пола
  if (gender && gender !== 'Мужской' && gender !== 'Женский') {
    console.log(gender);
    errors.push('Укажите корректный пол');
  }

  // Проверка номера телефона
  if (phone) {
    console.log(phone);
    const phoneRegex = /^(\+7|8)?[-. ]?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{2}[-. ]?\d{2}$/;
    if (!phoneRegex.test(phone)) {
      console.log(phone);
      errors.push('Недопустимый формат номера телефона');
    }
  }
  console.log(errors);

  return { success: errors.length === 0, errors };
};


module.exports = { validateSmen };
