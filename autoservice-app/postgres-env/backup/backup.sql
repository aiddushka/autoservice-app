--
-- PostgreSQL database dump
--

\restrict ihOa6finBbcawjePdSqRCs0UUMb7YGf6kuZbxague3wHguNT29MBKWmfVdjrMaP

-- Dumped from database version 17.6
-- Dumped by pg_dump version 17.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: apply_data_masking(bytea, character varying, integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.apply_data_masking(p_encrypted_data bytea, p_data_type character varying, p_employee_id integer DEFAULT NULL::integer) RETURNS text
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    v_current_user TEXT;
    v_current_employee_id INT;
    v_decrypted_data TEXT;
    v_is_hr BOOLEAN;
    v_is_security BOOLEAN;
    v_is_department_head BOOLEAN;
    v_data_owner_department INT;
    v_current_department INT;
BEGIN
    -- Получаем текущего пользователя и его ID
    v_current_user := current_user;
    
    SELECT get_current_employee_id() INTO v_current_employee_id;
    
    -- Проверяем роли
    SELECT EXISTS (
        SELECT 1 FROM pg_roles r 
        JOIN pg_auth_members m ON r.oid = m.roleid 
        JOIN pg_roles u ON u.oid = m.member 
        WHERE u.rolname = v_current_user AND r.rolname IN ('manager', 'superadmin')
    ) INTO v_is_hr;
    
    SELECT EXISTS (
        SELECT 1 FROM pg_roles r 
        JOIN pg_auth_members m ON r.oid = m.roleid 
        JOIN pg_roles u ON u.oid = m.member 
        WHERE u.rolname = v_current_user AND r.rolname = 'security_officer'
    ) INTO v_is_security;
    
    SELECT is_department_head() INTO v_is_department_head;
    SELECT get_current_department_id() INTO v_current_department;
    
    -- Если данные принадлежат текущему пользователю - показываем полностью
    IF p_employee_id IS NOT NULL AND p_employee_id = v_current_employee_id THEN
        RETURN decrypt_data(p_encrypted_data, p_data_type);
    END IF;
    
    -- Определяем отдел владельца данных
    IF p_employee_id IS NOT NULL THEN
        SELECT department_id INTO v_data_owner_department
        FROM Employees WHERE EmployeeID = p_employee_id;
    END IF;
    
    -- Правила доступа в зависимости от роли и типа данных
    CASE 
        -- HR (manager) видит все телефоны, но маскированные email
        WHEN v_is_hr THEN
            IF p_data_type = 'phone' THEN
                RETURN decrypt_data(p_encrypted_data, p_data_type);
            ELSIF p_data_type = 'email' THEN
                RETURN mask_email(decrypt_data(p_encrypted_data, p_data_type));
            ELSE
                RETURN decrypt_data(p_encrypted_data, p_data_type);
            END IF;
        
        -- Security officer видит все email, но маскированные телефоны
        WHEN v_is_security THEN
            IF p_data_type = 'email' THEN
                RETURN decrypt_data(p_encrypted_data, p_data_type);
            ELSIF p_data_type = 'phone' THEN
                RETURN mask_phone(decrypt_data(p_encrypted_data, p_data_type));
            ELSE
                RETURN decrypt_data(p_encrypted_data, p_data_type);
            END IF;
        
        -- Начальник отдела видит телефоны своих сотрудников, но маскированные email
        WHEN v_is_department_head AND v_data_owner_department = v_current_department THEN
            IF p_data_type = 'phone' THEN
                RETURN decrypt_data(p_encrypted_data, p_data_type);
            ELSIF p_data_type = 'email' THEN
                RETURN mask_email(decrypt_data(p_encrypted_data, p_data_type));
            ELSE
                RETURN mask_address(decrypt_data(p_encrypted_data, p_data_type));
            END IF;
        
        -- Остальные видят только маскированные данные
        ELSE
            CASE p_data_type
                WHEN 'email' THEN RETURN mask_email(decrypt_data(p_encrypted_data, p_data_type));
                WHEN 'phone' THEN RETURN mask_phone(decrypt_data(p_encrypted_data, p_data_type));
                WHEN 'address' THEN RETURN mask_address(decrypt_data(p_encrypted_data, p_data_type));
                ELSE RETURN '*** MASKED ***';
            END CASE;
    END CASE;
    
    RETURN '*** ACCESS DENIED ***';
EXCEPTION
    WHEN OTHERS THEN
        RETURN '*** MASKED ***';
END;
$$;


ALTER FUNCTION public.apply_data_masking(p_encrypted_data bytea, p_data_type character varying, p_employee_id integer) OWNER TO postgres;

--
-- Name: auto_set_department(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.auto_set_department() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Если creatorid не установлен, устанавливаем ID текущего сотрудника
    IF NEW.creatorid IS NULL THEN
        NEW.creatorid := get_current_employee_id();
    END IF;

    -- Если department_id не установлен, устанавливаем отдел текущего пользователя
    IF NEW.department_id IS NULL THEN
        NEW.department_id := get_current_department_id();
    END IF;
    
    -- Проверяем, что отдел установлен
    IF NEW.department_id IS NULL THEN
        RAISE EXCEPTION 'Не удалось автоматически определить отдел. department_id должен быть указан явно.';
    END IF;

    -- Проверяем, что creatorid установлен
    IF NEW.creatorid IS NULL THEN
        RAISE EXCEPTION 'Не удалось автоматически определить создателя. creatorid должен быть указан явно.';
    END IF;
    
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.auto_set_department() OWNER TO postgres;

--
-- Name: change_employee_password(integer, text, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.change_employee_password(p_employee_id integer, p_login text, p_new_password text) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_hash TEXT;
BEGIN
    -- Проверка политики
    PERFORM check_password_policy(p_login, p_new_password);

    -- Хэш пароля (используем md5 для учебных целей)
    v_hash := md5(p_new_password);

    -- Проверка истории
    PERFORM check_password_history(p_employee_id, v_hash);

    -- Обновление записи в EmployeeAccess
    UPDATE EmployeeAccess
    SET 
        PasswordHash = v_hash,
        PasswordChangedDate = NOW(),
        PasswordCompliant = TRUE,
        ForcePasswordChange = FALSE
    WHERE EmployeeID = p_employee_id;

    -- Добавление записи в историю паролей (новую таблицу)
    INSERT INTO password_history (employee_id, password_hash, change_date, changed_by)
    VALUES (p_employee_id, v_hash, NOW(), p_employee_id);

    RAISE NOTICE 'Пароль успешно изменён';
END;
$$;


ALTER FUNCTION public.change_employee_password(p_employee_id integer, p_login text, p_new_password text) OWNER TO postgres;

--
-- Name: change_employee_password_secure(integer, text, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.change_employee_password_secure(p_employee_id integer, p_login text, p_new_password text) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_current_user TEXT;
    v_employee_login TEXT;
    v_hash TEXT;
    v_is_security_officer BOOLEAN;
BEGIN
    -- Получаем текущего пользователя
    v_current_user := current_user;
    
    -- Проверяем, является ли пользователь security_officer
    SELECT EXISTS (
        SELECT 1 FROM pg_roles r 
        JOIN pg_auth_members m ON r.oid = m.roleid 
        JOIN pg_roles u ON u.oid = m.member 
        WHERE u.rolname = v_current_user AND r.rolname = 'security_officer'
    ) INTO v_is_security_officer;
    
    -- Получаем логин сотрудника по ID
    SELECT SystemLogin INTO v_employee_login
    FROM EmployeeAccess 
    WHERE EmployeeID = p_employee_id;
    
    -- Проверяем права: либо пользователь меняет свой пароль, либо он security_officer
    IF v_current_user != v_employee_login AND NOT v_is_security_officer THEN
        RAISE EXCEPTION 'Недостаточно прав для смены пароля другого пользователя';
    END IF;

    -- Проверка политики пароля
    PERFORM check_password_policy(p_login, p_new_password);

    -- Используем md5 для хэширования (как было изначально)
    v_hash := md5(p_new_password);

    -- Проверка истории паролей
    PERFORM check_password_history(p_employee_id, v_hash);

    -- Обновление записи в EmployeeAccess
    UPDATE EmployeeAccess
    SET 
        PasswordHash = v_hash,
        PasswordChangedDate = NOW(),
        PasswordCompliant = TRUE,
        ForcePasswordChange = FALSE
    WHERE EmployeeID = p_employee_id;

    -- Добавление записи в историю паролей
    INSERT INTO password_history (employee_id, password_hash, change_date, changed_by)
    VALUES (p_employee_id, v_hash, NOW(), p_employee_id);

    RAISE NOTICE 'Пароль успешно изменён';
END;
$$;


ALTER FUNCTION public.change_employee_password_secure(p_employee_id integer, p_login text, p_new_password text) OWNER TO postgres;

--
-- Name: check_password_history(integer, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.check_password_history(p_employee_id integer, p_new_hash text) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    cnt INT;
BEGIN
    SELECT COUNT(*) INTO cnt
    FROM password_history
    WHERE employee_id = p_employee_id
      AND password_hash = p_new_hash;

    IF cnt > 0 THEN
        RAISE EXCEPTION 'Нельзя использовать ранее использованный пароль';
    END IF;

    RETURN true;
END;
$$;


ALTER FUNCTION public.check_password_history(p_employee_id integer, p_new_hash text) OWNER TO postgres;

--
-- Name: check_password_policy(text, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.check_password_policy(p_login text, p_password text) RETURNS boolean
    LANGUAGE plpgsql
    AS $_$
BEGIN
    -- Минимальная длина
    IF length(p_password) < 8 THEN
        RAISE EXCEPTION 'Пароль должен содержать не менее 8 символов';
    END IF;

    -- Цифра
    IF p_password !~ '\d' THEN
        RAISE EXCEPTION 'Пароль должен содержать хотя бы одну цифру';
    END IF;

    -- Заглавная буква
    IF p_password !~ '[A-Z]' THEN
        RAISE EXCEPTION 'Пароль должен содержать хотя бы одну заглавную букву';
    END IF;

    -- Строчная буква
    IF p_password !~ '[a-z]' THEN
        RAISE EXCEPTION 'Пароль должен содержать хотя бы одну строчную букву';
    END IF;

    -- Спецсимвол
    IF p_password !~ '[!@#$%^&*()_+\-=\[\]{};":\\|,.<>\/?]' THEN
        RAISE EXCEPTION 'Пароль должен содержать хотя бы один специальный символ';
    END IF;

    -- Не совпадает с логином
    IF lower(p_password) = lower(p_login) THEN
        RAISE EXCEPTION 'Пароль не должен совпадать с логином';
    END IF;

    RETURN true;
END;
$_$;


ALTER FUNCTION public.check_password_policy(p_login text, p_password text) OWNER TO postgres;

--
-- Name: debug_current_user(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.debug_current_user() RETURNS TABLE(current_user_text text, current_role_text text, session_user_text text, found_employee_id integer)
    LANGUAGE plpgsql STABLE
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        current_user::TEXT,
        current_role::TEXT,
        session_user::TEXT,
        COALESCE(ea.employeeid, 0)::INT
    FROM employeeaccess ea
    WHERE ea.systemlogin = current_role;
END;
$$;


ALTER FUNCTION public.debug_current_user() OWNER TO postgres;

--
-- Name: decrypt_data(bytea, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.decrypt_data(p_encrypted_data bytea, p_key_type character varying) RETURNS text
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    AS $$
BEGIN
    IF p_encrypted_data IS NULL THEN
        RETURN NULL;
    END IF;
    
    RETURN pgp_sym_decrypt(
        p_encrypted_data, 
        get_encryption_key(p_key_type),
        'cipher-algo=aes256'
    );
END;
$$;


ALTER FUNCTION public.decrypt_data(p_encrypted_data bytea, p_key_type character varying) OWNER TO postgres;

--
-- Name: encrypt_data(text, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.encrypt_data(p_data text, p_key_type character varying) RETURNS bytea
    LANGUAGE plpgsql STABLE
    AS $$
BEGIN
    IF p_data IS NULL THEN
        RETURN NULL;
    END IF;
    
    RETURN pgp_sym_encrypt(
        p_data, 
        get_encryption_key(p_key_type),
        'cipher-algo=aes256'
    );
END;
$$;


ALTER FUNCTION public.encrypt_data(p_data text, p_key_type character varying) OWNER TO postgres;

--
-- Name: fn_add_car(integer, integer, integer, character varying, character varying, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_add_car(p_clientid integer, p_modelid integer, p_year integer, p_vin character varying, p_license character varying, p_color character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO Cars (ClientID, ModelID, Year, VIN, LicensePlate, Color)
    VALUES (p_clientid, p_modelid, p_year, p_vin, p_license, p_color);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('Cars', 'INSERT', current_user, jsonb_build_object('VIN', p_vin));
END;
$$;


ALTER FUNCTION public.fn_add_car(p_clientid integer, p_modelid integer, p_year integer, p_vin character varying, p_license character varying, p_color character varying) OWNER TO postgres;

--
-- Name: fn_add_client(character varying, character varying, character varying, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_add_client(p_fullname character varying, p_phone character varying, p_email character varying, p_address character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO Clients (FullName, Phone, Email, Address, RegistrationDate)
    VALUES (p_fullname, p_phone, p_email, p_address, CURRENT_DATE);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('Clients', 'INSERT', current_user,
            jsonb_build_object('FullName', p_fullname, 'RegistrationDate', CURRENT_DATE));
END;
$$;


ALTER FUNCTION public.fn_add_client(p_fullname character varying, p_phone character varying, p_email character varying, p_address character varying) OWNER TO postgres;

--
-- Name: fn_add_client(text, text, text, text, date); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_add_client(p_fullname text, p_phone text, p_email text, p_address text, p_registration_date date) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO Clients (FullName, Phone, Email, Address, RegistrationDate)
    VALUES (p_fullname, p_phone, p_email, p_address, p_registration_date);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES (
        'Clients',
        'INSERT',
        current_user,
        jsonb_build_object(
            'FullName', p_fullname,
            'Phone', p_phone,
            'Email', p_email,
            'Address', p_address,
            'RegistrationDate', p_registration_date
        )
    );
END;
$$;


ALTER FUNCTION public.fn_add_client(p_fullname text, p_phone text, p_email text, p_address text, p_registration_date date) OWNER TO postgres;

--
-- Name: fn_add_department(character varying, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_add_department(p_name character varying, p_desc text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO departments (department_name, description)
    VALUES (p_name, p_desc);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('departments', 'INSERT', current_user, jsonb_build_object('Name', p_name));
END;
$$;


ALTER FUNCTION public.fn_add_department(p_name character varying, p_desc text) OWNER TO postgres;

--
-- Name: fn_add_employee(character varying, character varying, character varying, character varying, integer, date, numeric); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_add_employee(p_fullname character varying, p_position character varying, p_phone character varying, p_email character varying, p_department_id integer, p_hiredate date, p_salary numeric) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO Employees (FullName, Position, Phone, Email, department_id, HireDate, Salary)
    VALUES (p_fullname, p_position, p_phone, p_email, p_department_id, p_hiredate, p_salary);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('Employees', 'INSERT', current_user,
        jsonb_build_object(
            'FullName', p_fullname,
            'Position', p_position,
            'Phone', p_phone,
            'Email', p_email,
            'department_id', p_department_id,
            'HireDate', p_hiredate,
            'Salary', p_salary
        ));
END;
$$;


ALTER FUNCTION public.fn_add_employee(p_fullname character varying, p_position character varying, p_phone character varying, p_email character varying, p_department_id integer, p_hiredate date, p_salary numeric) OWNER TO postgres;

--
-- Name: fn_add_make(character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_add_make(p_name character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO Makes (MakeName)
    VALUES (p_name);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('Makes', 'INSERT', current_user, jsonb_build_object('MakeName', p_name));
END;
$$;


ALTER FUNCTION public.fn_add_make(p_name character varying) OWNER TO postgres;

--
-- Name: fn_add_model(integer, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_add_model(p_makeid integer, p_modelname character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO Models (MakeID, ModelName)
    VALUES (p_makeid, p_modelname);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('Models', 'INSERT', current_user, jsonb_build_object('ModelName', p_modelname, 'MakeID', p_makeid));
END;
$$;


ALTER FUNCTION public.fn_add_model(p_makeid integer, p_modelname character varying) OWNER TO postgres;

--
-- Name: fn_add_order(integer, integer, date, character varying, numeric); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_add_order(p_carid integer, p_employeeid integer, p_orderdate date DEFAULT CURRENT_DATE, p_status character varying DEFAULT 'Новый'::character varying, p_totalamount numeric DEFAULT 0) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Проверяем существование машины
    IF NOT EXISTS (SELECT 1 FROM cars WHERE carid = p_carid) THEN
        RAISE EXCEPTION 'Машина с ID % не существует', p_carid;
    END IF;
    
    -- Проверяем существование сотрудника
    IF NOT EXISTS (SELECT 1 FROM employees WHERE employeeid = p_employeeid) THEN
        RAISE EXCEPTION 'Сотрудник с ID % не существует', p_employeeid;
    END IF;

    INSERT INTO Orders (carid, employeeid, orderdate, status, totalamount)
    VALUES (p_carid, p_employeeid, p_orderdate, p_status, p_totalamount);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('Orders', 'INSERT', current_user, jsonb_build_object(
        'CarID', p_carid,
        'EmployeeID', p_employeeid,
        'OrderDate', p_orderdate,
        'Status', p_status
    ));
END;
$$;


ALTER FUNCTION public.fn_add_order(p_carid integer, p_employeeid integer, p_orderdate date, p_status character varying, p_totalamount numeric) OWNER TO postgres;

--
-- Name: fn_add_order_service(integer, integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_add_order_service(p_orderid integer, p_serviceid integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO OrderServices (OrderID, ServiceID)
    VALUES (p_orderid, p_serviceid);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('OrderServices', 'INSERT', current_user, jsonb_build_object('OrderID', p_orderid, 'ServiceID', p_serviceid));
END;
$$;


ALTER FUNCTION public.fn_add_order_service(p_orderid integer, p_serviceid integer) OWNER TO postgres;

--
-- Name: fn_add_service(character varying, text, numeric, integer, integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_add_service(p_servicename character varying, p_description text, p_price numeric, p_durationminutes integer, p_categoryid integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO Services (servicename, description, price, durationminutes, categoryid)
    VALUES (p_servicename, p_description, p_price, p_durationminutes, p_categoryid);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('Services', 'INSERT', current_user, jsonb_build_object('ServiceName', p_servicename));
END;
$$;


ALTER FUNCTION public.fn_add_service(p_servicename character varying, p_description text, p_price numeric, p_durationminutes integer, p_categoryid integer) OWNER TO postgres;

--
-- Name: fn_add_service_category(character varying, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_add_service_category(p_name character varying, p_description text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO ServiceCategories (CategoryName, Description)
    VALUES (p_name, p_description);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('ServiceCategories', 'INSERT', current_user, jsonb_build_object('CategoryName', p_name));
END;
$$;


ALTER FUNCTION public.fn_add_service_category(p_name character varying, p_description text) OWNER TO postgres;

--
-- Name: fn_delete_car(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_delete_car(p_carid integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM Cars WHERE CarID = p_carid;

    INSERT INTO audit_log (table_name, action_type, user_name, old_data)
    VALUES ('Cars', 'DELETE', current_user, jsonb_build_object('CarID', p_carid));
END;
$$;


ALTER FUNCTION public.fn_delete_car(p_carid integer) OWNER TO postgres;

--
-- Name: fn_delete_client(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_delete_client(p_clientid integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM Clients WHERE ClientID = p_clientid;

    INSERT INTO audit_log (table_name, action_type, user_name, old_data)
    VALUES (
        'Clients',
        'DELETE',
        current_user,
        jsonb_build_object('ClientID', p_clientid)
    );
END;
$$;


ALTER FUNCTION public.fn_delete_client(p_clientid integer) OWNER TO postgres;

--
-- Name: fn_delete_confidential_document(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_delete_confidential_document(p_docid integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM confidentialdocuments WHERE docid = p_docid;

    INSERT INTO audit_log (table_name, action_type, user_name, old_data)
    VALUES (
        'confidentialdocuments',
        'DELETE',
        current_user,
        jsonb_build_object('docid', p_docid)
    );
END;
$$;


ALTER FUNCTION public.fn_delete_confidential_document(p_docid integer) OWNER TO postgres;

--
-- Name: fn_delete_employee(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_delete_employee(p_employee_id integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM Employees WHERE EmployeeID = p_employee_id;
    INSERT INTO audit_log (table_name, action_type, user_name, old_data)
    VALUES ('Employees', 'DELETE', current_user,
        jsonb_build_object('EmployeeID', p_employee_id));
END;
$$;


ALTER FUNCTION public.fn_delete_employee(p_employee_id integer) OWNER TO postgres;

--
-- Name: fn_delete_employee_role(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_delete_employee_role(p_employee_role_id integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM employee_roles WHERE employee_role_id = p_employee_role_id;

    INSERT INTO audit_log (table_name, action_type, user_name, old_data)
    VALUES (
        'employee_roles',
        'DELETE',
        current_user,
        jsonb_build_object('employee_role_id', p_employee_role_id)
    );
END;
$$;


ALTER FUNCTION public.fn_delete_employee_role(p_employee_role_id integer) OWNER TO postgres;

--
-- Name: fn_delete_employeeaccess(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_delete_employeeaccess(p_accessid integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM employeeaccess WHERE accessid = p_accessid;

    INSERT INTO audit_log (table_name, action_type, user_name, old_data)
    VALUES (
        'employeeaccess',
        'DELETE',
        current_user,
        jsonb_build_object('accessid', p_accessid)
    );
END;
$$;


ALTER FUNCTION public.fn_delete_employeeaccess(p_accessid integer) OWNER TO postgres;

--
-- Name: fn_delete_make(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_delete_make(p_id integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM Makes WHERE MakeID = p_id;

    INSERT INTO audit_log (table_name, action_type, user_name, old_data)
    VALUES ('Makes', 'DELETE', current_user, jsonb_build_object('MakeID', p_id));
END;
$$;


ALTER FUNCTION public.fn_delete_make(p_id integer) OWNER TO postgres;

--
-- Name: fn_delete_model(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_delete_model(p_id integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM Models WHERE ModelID = p_id;

    INSERT INTO audit_log (table_name, action_type, user_name, old_data)
    VALUES ('Models', 'DELETE', current_user, jsonb_build_object('ModelID', p_id));
END;
$$;


ALTER FUNCTION public.fn_delete_model(p_id integer) OWNER TO postgres;

--
-- Name: fn_delete_order(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_delete_order(p_orderid integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Проверяем существование заказа
    IF NOT EXISTS (SELECT 1 FROM orders WHERE orderid = p_orderid) THEN
        RAISE EXCEPTION 'Заказ с ID % не существует', p_orderid;
    END IF;

    DELETE FROM Orders WHERE orderid = p_orderid;

    INSERT INTO audit_log (table_name, action_type, user_name, old_data)
    VALUES ('Orders', 'DELETE', current_user, jsonb_build_object('OrderID', p_orderid));
END;
$$;


ALTER FUNCTION public.fn_delete_order(p_orderid integer) OWNER TO postgres;

--
-- Name: fn_delete_order_service(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_delete_order_service(p_orderserviceid integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM OrderServices WHERE OrderServiceID = p_orderserviceid;

    INSERT INTO audit_log (table_name, action_type, user_name, old_data)
    VALUES ('OrderServices', 'DELETE', current_user, jsonb_build_object('OrderServiceID', p_orderserviceid));
END;
$$;


ALTER FUNCTION public.fn_delete_order_service(p_orderserviceid integer) OWNER TO postgres;

--
-- Name: fn_delete_permission(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_delete_permission(p_permission_id integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM permissions WHERE permission_id = p_permission_id;

    INSERT INTO audit_log (table_name, action_type, user_name, old_data)
    VALUES (
        'permissions',
        'DELETE',
        current_user,
        jsonb_build_object('permission_id', p_permission_id)
    );
END;
$$;


ALTER FUNCTION public.fn_delete_permission(p_permission_id integer) OWNER TO postgres;

--
-- Name: fn_delete_service(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_delete_service(p_serviceid integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM Services WHERE serviceid = p_serviceid;

    INSERT INTO audit_log (table_name, action_type, user_name, old_data)
    VALUES ('Services', 'DELETE', current_user, jsonb_build_object('ServiceID', p_serviceid));
END;
$$;


ALTER FUNCTION public.fn_delete_service(p_serviceid integer) OWNER TO postgres;

--
-- Name: fn_delete_service_category(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_delete_service_category(p_id integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM ServiceCategories WHERE CategoryID = p_id;

    INSERT INTO audit_log (table_name, action_type, user_name, old_data)
    VALUES ('ServiceCategories', 'DELETE', current_user, jsonb_build_object('CategoryID', p_id));
END;
$$;


ALTER FUNCTION public.fn_delete_service_category(p_id integer) OWNER TO postgres;

--
-- Name: fn_get_all_cars(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_all_cars() RETURNS TABLE(carid integer, car_info character varying, client_name character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY 
    SELECT 
        c.carid, 
        (CONCAT(mk.makename, ' ', md.modelname, ' (', COALESCE(c.vin, 'без VIN'), ')'))::VARCHAR AS car_info,
        cl.fullname::VARCHAR AS client_name
    FROM cars c
    JOIN models md ON c.modelid = md.modelid
    JOIN makes mk ON md.makeid = mk.makeid
    JOIN clients cl ON c.clientid = cl.clientid
    ORDER BY mk.makename, md.modelname;
END;
$$;


ALTER FUNCTION public.fn_get_all_cars() OWNER TO postgres;

--
-- Name: fn_get_all_clients(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_all_clients() RETURNS TABLE(clientid integer, fullname character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY SELECT c.clientid, c.fullname FROM clients c ORDER BY c.fullname;
END;
$$;


ALTER FUNCTION public.fn_get_all_clients() OWNER TO postgres;

--
-- Name: fn_get_all_employees(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_all_employees() RETURNS TABLE(employeeid integer, fullname character varying, "position" character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY 
    SELECT e.employeeid, e.fullname, e.position 
    FROM employees e 
    ORDER BY e.fullname;
END;
$$;


ALTER FUNCTION public.fn_get_all_employees() OWNER TO postgres;

--
-- Name: fn_get_all_makes(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_all_makes() RETURNS TABLE(makeid integer, makename character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY 
    SELECT m.makeid, m.makename 
    FROM makes m 
    ORDER BY m.makename;
END;
$$;


ALTER FUNCTION public.fn_get_all_makes() OWNER TO postgres;

--
-- Name: fn_get_all_models(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_all_models() RETURNS TABLE(modelid integer, modelname character varying, makename character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY 
    SELECT m.modelid, m.modelname, mk.makename 
    FROM models m 
    JOIN makes mk ON m.makeid = mk.makeid 
    ORDER BY mk.makename, m.modelname;
END;
$$;


ALTER FUNCTION public.fn_get_all_models() OWNER TO postgres;

--
-- Name: fn_get_all_orders(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_all_orders() RETURNS TABLE(orderid integer, order_info character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY 
    SELECT 
        o.orderid, 
        (CONCAT('Заказ #', o.orderid, ' - ', cl.fullname, ' - ', mk.makename, ' ', md.modelname))::VARCHAR AS order_info
    FROM orders o
    JOIN cars c ON o.carid = c.carid
    JOIN models md ON c.modelid = md.modelid
    JOIN makes mk ON md.makeid = mk.makeid
    JOIN clients cl ON c.clientid = cl.clientid
    ORDER BY o.orderid;
END;
$$;


ALTER FUNCTION public.fn_get_all_orders() OWNER TO postgres;

--
-- Name: fn_get_all_service_categories(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_all_service_categories() RETURNS TABLE(categoryid integer, categoryname character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY 
    SELECT sc.categoryid, sc.categoryname 
    FROM servicecategories sc 
    ORDER BY sc.categoryname;
END;
$$;


ALTER FUNCTION public.fn_get_all_service_categories() OWNER TO postgres;

--
-- Name: fn_get_all_services(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_all_services() RETURNS TABLE(serviceid integer, servicename character varying, categoryname character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY 
    SELECT s.serviceid, s.servicename, sc.categoryname 
    FROM services s 
    JOIN servicecategories sc ON s.categoryid = sc.categoryid 
    ORDER BY sc.categoryname, s.servicename;
END;
$$;


ALTER FUNCTION public.fn_get_all_services() OWNER TO postgres;

--
-- Name: fn_get_car_by_id(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_car_by_id(p_carid integer) RETURNS TABLE(carid integer, clientid integer, modelid integer, year integer, vin character varying, licenseplate character varying, color character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT c.carid, c.clientid, c.modelid, c.year, c.vin, c.licenseplate, c.color
    FROM cars c
    WHERE c.carid = p_carid;
END;
$$;


ALTER FUNCTION public.fn_get_car_by_id(p_carid integer) OWNER TO postgres;

--
-- Name: fn_get_client_by_id(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_client_by_id(p_clientid integer) RETURNS TABLE(clientid integer, fullname character varying, phone character varying, email character varying, address character varying, registrationdate date)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT c.clientid, c.fullname, c.phone, c.email, c.address, c.registrationdate
    FROM clients c
    WHERE c.clientid = p_clientid;
END;
$$;


ALTER FUNCTION public.fn_get_client_by_id(p_clientid integer) OWNER TO postgres;

--
-- Name: fn_get_department_by_id(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_department_by_id(p_department_id integer) RETURNS TABLE(department_id integer, department_name character varying, description text, manager_id integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT d.department_id, d.department_name, d.description, d.manager_id
    FROM departments d
    WHERE d.department_id = p_department_id;
END;
$$;


ALTER FUNCTION public.fn_get_department_by_id(p_department_id integer) OWNER TO postgres;

--
-- Name: fn_get_employee_by_id(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_employee_by_id(p_employeeid integer) RETURNS TABLE(employeeid integer, fullname character varying, "position" character varying, phone character varying, email character varying, department_id integer, hiredate date, salary numeric)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT e.employeeid, e.fullname, e.position, e.phone, e.email, 
           e.department_id, e.hiredate, e.salary
    FROM employees e
    WHERE e.employeeid = p_employeeid;
END;
$$;


ALTER FUNCTION public.fn_get_employee_by_id(p_employeeid integer) OWNER TO postgres;

--
-- Name: fn_get_make_by_id(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_make_by_id(p_makeid integer) RETURNS TABLE(makeid integer, makename character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT m.makeid, m.makename
    FROM makes m
    WHERE m.makeid = p_makeid;
END;
$$;


ALTER FUNCTION public.fn_get_make_by_id(p_makeid integer) OWNER TO postgres;

--
-- Name: fn_get_model_by_id(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_model_by_id(p_modelid integer) RETURNS TABLE(modelid integer, makeid integer, modelname character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT m.modelid, m.makeid, m.modelname
    FROM models m
    WHERE m.modelid = p_modelid;
END;
$$;


ALTER FUNCTION public.fn_get_model_by_id(p_modelid integer) OWNER TO postgres;

--
-- Name: fn_get_order_by_id(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_order_by_id(p_orderid integer) RETURNS TABLE(orderid integer, carid integer, employeeid integer, orderdate date, status character varying, totalamount numeric)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT o.orderid, o.carid, o.employeeid, o.orderdate, o.status, o.totalamount
    FROM orders o
    WHERE o.orderid = p_orderid;
END;
$$;


ALTER FUNCTION public.fn_get_order_by_id(p_orderid integer) OWNER TO postgres;

--
-- Name: fn_get_order_by_id_view(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_order_by_id_view(p_orderid integer) RETURNS TABLE(orderid integer, client_name character varying, car_info character varying, employee_name character varying, orderdate date, status character varying, totalamount numeric)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        o."orderid",
        o."Клиент"::VARCHAR,
        o."Автомобиль"::VARCHAR,
        o."Ответственный сотрудник"::VARCHAR,
        o."Дата заказа",
        o."Статус"::VARCHAR,
        o."Сумма"
    FROM v_orders o
    WHERE o."orderid" = p_orderid;
END;
$$;


ALTER FUNCTION public.fn_get_order_by_id_view(p_orderid integer) OWNER TO postgres;

--
-- Name: fn_get_order_for_edit(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_order_for_edit(p_orderid integer) RETURNS TABLE(orderid integer, car_info character varying, client_name character varying, employee_name character varying, orderdate date, status character varying, totalamount numeric)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        o."OrderID",
        o."Автомобиль"::VARCHAR,
        o."Клиент"::VARCHAR,
        o."Ответственный сотрудник"::VARCHAR,
        o."Дата заказа",
        o."Статус"::VARCHAR,
        o."Сумма"
    FROM v_orders o
    WHERE o."OrderID" = p_orderid;
END;
$$;


ALTER FUNCTION public.fn_get_order_for_edit(p_orderid integer) OWNER TO postgres;

--
-- Name: fn_get_orderservice_by_id(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_orderservice_by_id(p_orderserviceid integer) RETURNS TABLE(orderserviceid integer, orderid integer, serviceid integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT os.orderserviceid, os.orderid, os.serviceid
    FROM orderservices os
    WHERE os.orderserviceid = p_orderserviceid;
END;
$$;


ALTER FUNCTION public.fn_get_orderservice_by_id(p_orderserviceid integer) OWNER TO postgres;

--
-- Name: fn_get_service_by_id(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_service_by_id(p_serviceid integer) RETURNS TABLE(serviceid integer, servicename character varying, description text, price numeric, durationminutes integer, categoryid integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT s.serviceid, s.servicename, s.description, s.price, s.durationminutes, s.categoryid
    FROM services s
    WHERE s.serviceid = p_serviceid;
END;
$$;


ALTER FUNCTION public.fn_get_service_by_id(p_serviceid integer) OWNER TO postgres;

--
-- Name: fn_get_servicecategory_by_id(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_servicecategory_by_id(p_categoryid integer) RETURNS TABLE(categoryid integer, categoryname character varying, description text)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT sc.categoryid, sc.categoryname, sc.description
    FROM servicecategories sc
    WHERE sc.categoryid = p_categoryid;
END;
$$;


ALTER FUNCTION public.fn_get_servicecategory_by_id(p_categoryid integer) OWNER TO postgres;

--
-- Name: fn_insert_confidential_document(character varying, integer, character varying, integer, date, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_insert_confidential_document(p_doctitle character varying, p_creatorid integer, p_accesslevel character varying, p_department_id integer, p_createddate date DEFAULT NULL::date, p_content text DEFAULT NULL::text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO confidentialdocuments (doctitle, creatorid, accesslevel, department_id, createddate, content)
    VALUES (p_doctitle, p_creatorid, p_accesslevel, p_department_id, COALESCE(p_createddate, CURRENT_DATE), p_content);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES (
        'confidentialdocuments',
        'INSERT',
        current_user,
        jsonb_build_object(
            'doctitle', p_doctitle,
            'creatorid', p_creatorid,
            'accesslevel', p_accesslevel,
            'department_id', p_department_id,
            'createddate', COALESCE(p_createddate, CURRENT_DATE),
            'content', p_content
        )
    );
END;
$$;


ALTER FUNCTION public.fn_insert_confidential_document(p_doctitle character varying, p_creatorid integer, p_accesslevel character varying, p_department_id integer, p_createddate date, p_content text) OWNER TO postgres;

--
-- Name: fn_insert_employee_role(integer, integer, integer, boolean); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_insert_employee_role(p_employee_id integer, p_role_id integer, p_assigned_by integer, p_is_active boolean DEFAULT true) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO employee_roles (employee_id, role_id, assigned_by, is_active)
    VALUES (p_employee_id, p_role_id, p_assigned_by, p_is_active);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES (
        'employee_roles',
        'INSERT',
        current_user,
        jsonb_build_object(
            'employee_id', p_employee_id,
            'role_id', p_role_id,
            'assigned_by', p_assigned_by,
            'is_active', p_is_active
        )
    );
END;
$$;


ALTER FUNCTION public.fn_insert_employee_role(p_employee_id integer, p_role_id integer, p_assigned_by integer, p_is_active boolean) OWNER TO postgres;

--
-- Name: fn_insert_employeeaccess(integer, character varying, date, boolean, boolean, boolean); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_insert_employeeaccess(p_employeeid integer, p_systemlogin character varying, p_issuedate date DEFAULT NULL::date, p_isactive boolean DEFAULT true, p_passwordcompliant boolean DEFAULT false, p_forcepasswordchange boolean DEFAULT true) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO employeeaccess (employeeid, systemlogin, issuedate, isactive, passwordcompliant, forcepasswordchange)
    VALUES (p_employeeid, p_systemlogin, COALESCE(p_issuedate, CURRENT_DATE), p_isactive, p_passwordcompliant, p_forcepasswordchange);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES (
        'employeeaccess',
        'INSERT',
        current_user,
        jsonb_build_object(
            'employeeid', p_employeeid,
            'systemlogin', p_systemlogin,
            'issuedate', COALESCE(p_issuedate, CURRENT_DATE),
            'isactive', p_isactive,
            'passwordcompliant', p_passwordcompliant,
            'forcepasswordchange', p_forcepasswordchange
        )
    );
END;
$$;


ALTER FUNCTION public.fn_insert_employeeaccess(p_employeeid integer, p_systemlogin character varying, p_issuedate date, p_isactive boolean, p_passwordcompliant boolean, p_forcepasswordchange boolean) OWNER TO postgres;

--
-- Name: fn_insert_permission(character varying, text, character varying, character varying, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_insert_permission(p_permission_name character varying, p_description text DEFAULT NULL::text, p_object_type character varying DEFAULT NULL::character varying, p_object_name character varying DEFAULT NULL::character varying, p_action character varying DEFAULT NULL::character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO permissions (permission_name, description, object_type, object_name, action)
    VALUES (p_permission_name, p_description, p_object_type, p_object_name, p_action);

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES (
        'permissions',
        'INSERT',
        current_user,
        jsonb_build_object(
            'permission_name', p_permission_name,
            'description', p_description,
            'object_type', p_object_type,
            'object_name', p_object_name,
            'action', p_action
        )
    );
END;
$$;


ALTER FUNCTION public.fn_insert_permission(p_permission_name character varying, p_description text, p_object_type character varying, p_object_name character varying, p_action character varying) OWNER TO postgres;

--
-- Name: fn_update_car(integer, integer, integer, integer, character varying, character varying, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_car(p_carid integer, p_clientid integer, p_modelid integer, p_year integer, p_vin character varying, p_license character varying, p_color character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE Cars
    SET 
        ClientID = p_clientid,
        ModelID = p_modelid,
        Year = p_year,
        VIN = p_vin,
        LicensePlate = p_license,
        Color = p_color
    WHERE CarID = p_carid;

    INSERT INTO audit_log (table_name, action_type, user_name, old_data, new_data)
    VALUES (
        'Cars',
        'UPDATE',
        current_user,
        jsonb_build_object('CarID', p_carid),
        jsonb_build_object('VIN', p_vin)
    );
END;
$$;


ALTER FUNCTION public.fn_update_car(p_carid integer, p_clientid integer, p_modelid integer, p_year integer, p_vin character varying, p_license character varying, p_color character varying) OWNER TO postgres;

--
-- Name: fn_update_client(integer, text, text, text, text, date); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_client(p_clientid integer, p_fullname text, p_phone text, p_email text, p_address text, p_registration_date date) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE Clients
    SET FullName = p_fullname,
        Phone = p_phone,
        Email = p_email,
        Address = p_address,
        RegistrationDate = p_registration_date
    WHERE ClientID = p_clientid;

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES (
        'Clients',
        'UPDATE',
        current_user,
        jsonb_build_object(
            'ClientID', p_clientid,
            'FullName', p_fullname,
            'Phone', p_phone,
            'Email', p_email,
            'Address', p_address,
            'RegistrationDate', p_registration_date
        )
    );
END;
$$;


ALTER FUNCTION public.fn_update_client(p_clientid integer, p_fullname text, p_phone text, p_email text, p_address text, p_registration_date date) OWNER TO postgres;

--
-- Name: fn_update_confidential_document(integer, character varying, integer, character varying, integer, date, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_confidential_document(p_docid integer, p_doctitle character varying, p_creatorid integer, p_accesslevel character varying, p_department_id integer, p_createddate date DEFAULT NULL::date, p_content text DEFAULT NULL::text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE confidentialdocuments 
    SET doctitle = p_doctitle,
        creatorid = p_creatorid,
        accesslevel = p_accesslevel,
        department_id = p_department_id,
        createddate = COALESCE(p_createddate, createddate),
        content = p_content
    WHERE docid = p_docid;

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES (
        'confidentialdocuments',
        'UPDATE',
        current_user,
        jsonb_build_object(
            'docid', p_docid,
            'doctitle', p_doctitle,
            'creatorid', p_creatorid,
            'accesslevel', p_accesslevel,
            'department_id', p_department_id,
            'createddate', COALESCE(p_createddate, createddate),
            'content', p_content
        )
    );
END;
$$;


ALTER FUNCTION public.fn_update_confidential_document(p_docid integer, p_doctitle character varying, p_creatorid integer, p_accesslevel character varying, p_department_id integer, p_createddate date, p_content text) OWNER TO postgres;

--
-- Name: fn_update_employee(integer, character varying, character varying, character varying, character varying, integer, date, numeric); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_employee(p_employee_id integer, p_fullname character varying, p_position character varying, p_phone character varying, p_email character varying, p_department_id integer, p_hiredate date, p_salary numeric) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE Employees
    SET FullName = p_fullname,
        Position = p_position,
        Phone = p_phone,
        Email = p_email,
        department_id = p_department_id,
        HireDate = p_hiredate,
        Salary = p_salary
    WHERE EmployeeID = p_employee_id;

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('Employees', 'UPDATE', current_user,
        jsonb_build_object(
            'EmployeeID', p_employee_id,
            'FullName', p_fullname,
            'Position', p_position,
            'Phone', p_phone,
            'Email', p_email,
            'department_id', p_department_id,
            'HireDate', p_hiredate,
            'Salary', p_salary
        ));
END;
$$;


ALTER FUNCTION public.fn_update_employee(p_employee_id integer, p_fullname character varying, p_position character varying, p_phone character varying, p_email character varying, p_department_id integer, p_hiredate date, p_salary numeric) OWNER TO postgres;

--
-- Name: fn_update_employee_role(integer, integer, integer, boolean); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_employee_role(p_employee_role_id integer, p_employee_id integer, p_role_id integer, p_is_active boolean) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE employee_roles 
    SET employee_id = p_employee_id,
        role_id = p_role_id,
        is_active = p_is_active
    WHERE employee_role_id = p_employee_role_id;

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES (
        'employee_roles',
        'UPDATE',
        current_user,
        jsonb_build_object(
            'employee_role_id', p_employee_role_id,
            'employee_id', p_employee_id,
            'role_id', p_role_id,
            'is_active', p_is_active
        )
    );
END;
$$;


ALTER FUNCTION public.fn_update_employee_role(p_employee_role_id integer, p_employee_id integer, p_role_id integer, p_is_active boolean) OWNER TO postgres;

--
-- Name: fn_update_employeeaccess(integer, integer, character varying, boolean, boolean, boolean); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_employeeaccess(p_accessid integer, p_employeeid integer, p_systemlogin character varying, p_isactive boolean, p_passwordcompliant boolean, p_forcepasswordchange boolean) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE employeeaccess 
    SET employeeid = p_employeeid,
        systemlogin = p_systemlogin,
        isactive = p_isactive,
        passwordcompliant = p_passwordcompliant,
        forcepasswordchange = p_forcepasswordchange
    WHERE accessid = p_accessid;

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES (
        'employeeaccess',
        'UPDATE',
        current_user,
        jsonb_build_object(
            'accessid', p_accessid,
            'employeeid', p_employeeid,
            'systemlogin', p_systemlogin,
            'isactive', p_isactive,
            'passwordcompliant', p_passwordcompliant,
            'forcepasswordchange', p_forcepasswordchange
        )
    );
END;
$$;


ALTER FUNCTION public.fn_update_employeeaccess(p_accessid integer, p_employeeid integer, p_systemlogin character varying, p_isactive boolean, p_passwordcompliant boolean, p_forcepasswordchange boolean) OWNER TO postgres;

--
-- Name: fn_update_make(integer, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_make(p_id integer, p_name character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE Makes
    SET MakeName = p_name
    WHERE MakeID = p_id;

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('Makes', 'UPDATE', current_user, jsonb_build_object('MakeID', p_id, 'MakeName', p_name));
END;
$$;


ALTER FUNCTION public.fn_update_make(p_id integer, p_name character varying) OWNER TO postgres;

--
-- Name: fn_update_model(integer, integer, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_model(p_modelid integer, p_makeid integer, p_modelname character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Проверяем существование марки
    IF NOT EXISTS (SELECT 1 FROM makes WHERE makeid = p_makeid) THEN
        RAISE EXCEPTION 'Марка с ID % не существует', p_makeid;
    END IF;

    -- Проверяем, не существует ли уже модели с таким названием у этой марки
    IF EXISTS (SELECT 1 FROM models WHERE makeid = p_makeid AND modelname = p_modelname AND modelid != p_modelid) THEN
        RAISE EXCEPTION 'Модель "%" уже существует у этой марки', p_modelname;
    END IF;

    UPDATE Models
    SET MakeID = p_makeid,
        ModelName = p_modelname
    WHERE ModelID = p_modelid;

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('Models', 'UPDATE', current_user, jsonb_build_object('ModelID', p_modelid, 'MakeID', p_makeid, 'ModelName', p_modelname));
END;
$$;


ALTER FUNCTION public.fn_update_model(p_modelid integer, p_makeid integer, p_modelname character varying) OWNER TO postgres;

--
-- Name: fn_update_order(integer, integer, integer, date, character varying, numeric); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_order(p_orderid integer, p_carid integer, p_employeeid integer, p_orderdate date, p_status character varying, p_totalamount numeric) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Проверяем существование заказа
    IF NOT EXISTS (SELECT 1 FROM orders WHERE orderid = p_orderid) THEN
        RAISE EXCEPTION 'Заказ с ID % не существует', p_orderid;
    END IF;
    
    -- Проверяем существование машины
    IF NOT EXISTS (SELECT 1 FROM cars WHERE carid = p_carid) THEN
        RAISE EXCEPTION 'Машина с ID % не существует', p_carid;
    END IF;
    
    -- Проверяем существование сотрудника
    IF NOT EXISTS (SELECT 1 FROM employees WHERE employeeid = p_employeeid) THEN
        RAISE EXCEPTION 'Сотрудник с ID % не существует', p_employeeid;
    END IF;

    UPDATE Orders 
    SET carid = p_carid,
        employeeid = p_employeeid,
        orderdate = p_orderdate,
        status = p_status,
        totalamount = p_totalamount
    WHERE orderid = p_orderid;

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('Orders', 'UPDATE', current_user, jsonb_build_object(
        'OrderID', p_orderid,
        'CarID', p_carid,
        'EmployeeID', p_employeeid,
        'OrderDate', p_orderdate,
        'Status', p_status
    ));
END;
$$;


ALTER FUNCTION public.fn_update_order(p_orderid integer, p_carid integer, p_employeeid integer, p_orderdate date, p_status character varying, p_totalamount numeric) OWNER TO postgres;

--
-- Name: fn_update_order_status(integer, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_order_status(p_orderid integer, p_status character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Проверяем существование заказа
    IF NOT EXISTS (SELECT 1 FROM orders WHERE orderid = p_orderid) THEN
        RAISE EXCEPTION 'Заказ с ID % не существует', p_orderid;
    END IF;

    UPDATE Orders 
    SET Status = p_status
    WHERE OrderID = p_orderid;

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('Orders', 'UPDATE', current_user, jsonb_build_object('OrderID', p_orderid, 'Status', p_status));
END;
$$;


ALTER FUNCTION public.fn_update_order_status(p_orderid integer, p_status character varying) OWNER TO postgres;

--
-- Name: fn_update_order_total(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_order_total() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Пересчитываем сумму по всем услугам, связанным с заказом
    UPDATE Orders
    SET TotalAmount = COALESCE((
        SELECT SUM(s.Price)
        FROM OrderServices os
        JOIN Services s ON s.ServiceID = os.ServiceID
        WHERE os.OrderID = NEW.OrderID
    ), 0)
    WHERE OrderID = NEW.OrderID;

    RETURN NULL;
END;
$$;


ALTER FUNCTION public.fn_update_order_total() OWNER TO postgres;

--
-- Name: fn_update_permission(integer, character varying, text, character varying, character varying, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_permission(p_permission_id integer, p_permission_name character varying, p_description text DEFAULT NULL::text, p_object_type character varying DEFAULT NULL::character varying, p_object_name character varying DEFAULT NULL::character varying, p_action character varying DEFAULT NULL::character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE permissions 
    SET permission_name = p_permission_name,
        description = p_description,
        object_type = p_object_type,
        object_name = p_object_name,
        action = p_action
    WHERE permission_id = p_permission_id;

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES (
        'permissions',
        'UPDATE',
        current_user,
        jsonb_build_object(
            'permission_id', p_permission_id,
            'permission_name', p_permission_name,
            'description', p_description,
            'object_type', p_object_type,
            'object_name', p_object_name,
            'action', p_action
        )
    );
END;
$$;


ALTER FUNCTION public.fn_update_permission(p_permission_id integer, p_permission_name character varying, p_description text, p_object_type character varying, p_object_name character varying, p_action character varying) OWNER TO postgres;

--
-- Name: fn_update_service(integer, character varying, text, numeric, integer, integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_service(p_serviceid integer, p_servicename character varying, p_description text, p_price numeric, p_durationminutes integer, p_categoryid integer) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE Services
    SET servicename = p_servicename,
        description = p_description,
        price = p_price,
        durationminutes = p_durationminutes,
        categoryid = p_categoryid
    WHERE serviceid = p_serviceid;

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('Services', 'UPDATE', current_user, jsonb_build_object('ServiceID', p_serviceid));
END;
$$;


ALTER FUNCTION public.fn_update_service(p_serviceid integer, p_servicename character varying, p_description text, p_price numeric, p_durationminutes integer, p_categoryid integer) OWNER TO postgres;

--
-- Name: fn_update_service_category(integer, character varying, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_update_service_category(p_id integer, p_name character varying, p_description text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE ServiceCategories
    SET CategoryName = p_name,
        Description = p_description
    WHERE CategoryID = p_id;

    INSERT INTO audit_log (table_name, action_type, user_name, new_data)
    VALUES ('ServiceCategories', 'UPDATE', current_user, jsonb_build_object('CategoryID', p_id, 'CategoryName', p_name));
END;
$$;


ALTER FUNCTION public.fn_update_service_category(p_id integer, p_name character varying, p_description text) OWNER TO postgres;

--
-- Name: get_current_department_id(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_current_department_id() RETURNS integer
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    v_department_id INT;
BEGIN
    SELECT e.department_id INTO v_department_id
    FROM employees e
    JOIN employeeaccess ea ON e.employeeid = ea.employeeid
    WHERE ea.systemlogin = current_role;  -- ИЗМЕНЕНИЕ: current_role вместо current_user
    
    RETURN COALESCE(v_department_id, 0);
END;
$$;


ALTER FUNCTION public.get_current_department_id() OWNER TO postgres;

--
-- Name: get_current_employee_id(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_current_employee_id() RETURNS integer
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    v_employee_id INT;
BEGIN
    SELECT employeeid INTO v_employee_id
    FROM employeeaccess
    WHERE systemlogin = current_role;  -- ИЗМЕНЕНИЕ: current_role вместо current_user
    
    RETURN COALESCE(v_employee_id, 0);
END;
$$;


ALTER FUNCTION public.get_current_employee_id() OWNER TO postgres;

--
-- Name: get_current_employee_role(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_current_employee_role() RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
    emp_role TEXT;
BEGIN
    SELECT r.role_name
    INTO emp_role
    FROM EmployeeAccess ea
    JOIN employee_roles er ON er.employee_id = ea.EmployeeID AND er.is_active = TRUE
    JOIN roles r ON r.role_id = er.role_id
    WHERE ea.SystemLogin = current_role
    LIMIT 1;

    RETURN emp_role;
END;
$$;


ALTER FUNCTION public.get_current_employee_role() OWNER TO postgres;

--
-- Name: get_encryption_key(character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_encryption_key(p_key_type character varying) RETURNS text
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    AS $$
DECLARE
    v_key TEXT;
BEGIN
    SELECT key_value INTO v_key
    FROM encryption_keys
    WHERE key_type = p_key_type AND is_active = TRUE
    ORDER BY key_version DESC
    LIMIT 1;
    
    IF v_key IS NULL THEN
        RAISE EXCEPTION 'Encryption key not found for type: %', p_key_type;
    END IF;
    
    RETURN v_key;
END;
$$;


ALTER FUNCTION public.get_encryption_key(p_key_type character varying) OWNER TO postgres;

--
-- Name: is_department_head(integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.is_department_head(p_department_id integer DEFAULT NULL::integer) RETURNS boolean
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    v_employee_id INT;
    v_count INT;
BEGIN
    v_employee_id := get_current_employee_id();
    
    IF p_department_id IS NOT NULL THEN
        -- Проверяем, является ли начальником конкретного отдела
        SELECT COUNT(*) INTO v_count
        FROM departments
        WHERE manager_id = v_employee_id AND department_id = p_department_id;
    ELSE
        -- Проверяем, является ли начальником любого отдела
        SELECT COUNT(*) INTO v_count
        FROM departments
        WHERE manager_id = v_employee_id;
    END IF;
    
    RETURN v_count > 0;
END;
$$;


ALTER FUNCTION public.is_department_head(p_department_id integer) OWNER TO postgres;

--
-- Name: is_weak_password(text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.is_weak_password(p_password text) RETURNS boolean
    LANGUAGE plpgsql
    AS $_$
BEGIN
    -- Проверяем простые условия без выброса исключений
    RETURN (
        length(p_password) < 8 OR
        p_password !~ '\d' OR
        p_password !~ '[A-Z]' OR 
        p_password !~ '[a-z]' OR
        p_password !~ '[!@#$%^&*()_+\-=\[\]{};":\\|,.<>\/?]' OR
        p_password IN ('password', 'qwerty', '123456', '12345678')
    );
END;
$_$;


ALTER FUNCTION public.is_weak_password(p_password text) OWNER TO postgres;

--
-- Name: log_encrypted_access(character varying, character varying, integer, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.log_encrypted_access(p_table_name character varying, p_action_type character varying, p_record_id integer, p_decrypted_field character varying) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO encrypted_data_access_log (
        table_name,
        action_type,
        user_name,
        record_id,
        decrypted_field
    ) VALUES (
        p_table_name,
        p_action_type,
        current_user,
        p_record_id,
        p_decrypted_field
    );
END;
$$;


ALTER FUNCTION public.log_encrypted_access(p_table_name character varying, p_action_type character varying, p_record_id integer, p_decrypted_field character varying) OWNER TO postgres;

--
-- Name: mask_address(text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.mask_address(address_text text) RETURNS text
    LANGUAGE plpgsql STABLE
    AS $_$
BEGIN
    IF address_text IS NULL THEN 
        RETURN NULL; 
    END IF;
    
    RETURN '*** ' || substring(address_text FROM '[^,]*$');
END;
$_$;


ALTER FUNCTION public.mask_address(address_text text) OWNER TO postgres;

--
-- Name: mask_email(text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.mask_email(email_text text) RETURNS text
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    parts TEXT[];
    username TEXT;
    domain TEXT;
BEGIN
    IF email_text IS NULL THEN 
        RETURN NULL; 
    END IF;
    
    parts := string_to_array(email_text, '@');
    IF array_length(parts, 1) = 2 THEN
        username := parts[1];
        domain := parts[2];
        
        IF length(username) <= 2 THEN
            RETURN substring(username FROM 1 FOR 1) || '***@' || domain;
        ELSE
            RETURN substring(username FROM 1 FOR 2) || '***@' || domain;
        END IF;
    END IF;
    
    RETURN '***@***';
END;
$$;


ALTER FUNCTION public.mask_email(email_text text) OWNER TO postgres;

--
-- Name: mask_phone(text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.mask_phone(phone_text text) RETURNS text
    LANGUAGE plpgsql STABLE
    AS $$
BEGIN
    IF phone_text IS NULL THEN 
        RETURN NULL; 
    END IF;
    
    IF length(phone_text) <= 4 THEN
        RETURN '***-' || substring(phone_text FROM length(phone_text)-3 FOR 4);
    ELSE
        RETURN '***-' || substring(phone_text FROM length(phone_text)-3 FOR 4);
    END IF;
END;
$$;


ALTER FUNCTION public.mask_phone(phone_text text) OWNER TO postgres;

--
-- Name: sync_pg_user(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.sync_pg_user() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO employeeaccess (systemlogin, isactive)
    SELECT u.usename, TRUE
    FROM pg_catalog.pg_user u
    WHERE u.usename NOT IN (SELECT systemlogin FROM employeeaccess);
END;
$$;


ALTER FUNCTION public.sync_pg_user() OWNER TO postgres;

--
-- Name: trigger_log_decryption(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.trigger_log_decryption() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM log_encrypted_access(
        TG_TABLE_NAME,
        TG_OP,
        COALESCE(NEW.EmployeeID, NEW.ClientID, NEW.DocID),
        'encrypted_field_accessed'
    );
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.trigger_log_decryption() OWNER TO postgres;

--
-- Name: view_department_managers(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.view_department_managers() RETURNS TABLE(department_name character varying, manager_name character varying, manager_id integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        d.department_name,
        e.fullname,
        d.manager_id
    FROM departments d
    LEFT JOIN employees e ON e.employeeid = d.manager_id
    ORDER BY d.department_name;
END;
$$;


ALTER FUNCTION public.view_department_managers() OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.audit_log (
    audit_id integer NOT NULL,
    table_name character varying(100) NOT NULL,
    action_type character varying(10) NOT NULL,
    user_name character varying(100) NOT NULL,
    action_timestamp timestamp without time zone DEFAULT now(),
    old_data jsonb,
    new_data jsonb,
    ip_address inet,
    CONSTRAINT audit_log_action_type_check CHECK (((action_type)::text = ANY ((ARRAY['INSERT'::character varying, 'UPDATE'::character varying, 'DELETE'::character varying])::text[])))
);


ALTER TABLE public.audit_log OWNER TO postgres;

--
-- Name: audit_log_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.audit_log_audit_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.audit_log_audit_id_seq OWNER TO postgres;

--
-- Name: audit_log_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.audit_log_audit_id_seq OWNED BY public.audit_log.audit_id;


--
-- Name: cars; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.cars (
    carid integer NOT NULL,
    clientid integer NOT NULL,
    modelid integer NOT NULL,
    year integer,
    vin character varying(50),
    licenseplate character varying(20),
    color character varying(30),
    CONSTRAINT cars_year_check CHECK (((year >= 1900) AND ((year)::numeric <= (EXTRACT(year FROM CURRENT_DATE) + (1)::numeric))))
);


ALTER TABLE public.cars OWNER TO postgres;

--
-- Name: cars_carid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.cars_carid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.cars_carid_seq OWNER TO postgres;

--
-- Name: cars_carid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.cars_carid_seq OWNED BY public.cars.carid;


--
-- Name: clients; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.clients (
    clientid integer NOT NULL,
    fullname character varying(100) NOT NULL,
    phone character varying(20),
    email character varying(100),
    address character varying(200),
    registrationdate date DEFAULT CURRENT_DATE,
    phone_encrypted bytea,
    email_encrypted bytea,
    address_encrypted bytea
);


ALTER TABLE public.clients OWNER TO postgres;

--
-- Name: clients_clientid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.clients_clientid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.clients_clientid_seq OWNER TO postgres;

--
-- Name: clients_clientid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.clients_clientid_seq OWNED BY public.clients.clientid;


--
-- Name: confidentialdocuments; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.confidentialdocuments (
    docid integer NOT NULL,
    doctitle character varying(200) NOT NULL,
    creatorid integer NOT NULL,
    createddate date DEFAULT CURRENT_DATE NOT NULL,
    content text,
    accesslevel character varying(20),
    department_id integer NOT NULL,
    content_encrypted bytea,
    CONSTRAINT confidentialdocuments_accesslevel_check CHECK (((accesslevel)::text = ANY ((ARRAY['Public'::character varying, 'Internal'::character varying, 'Confidential'::character varying, 'Strictly'::character varying])::text[])))
);


ALTER TABLE public.confidentialdocuments OWNER TO postgres;

--
-- Name: confidentialdocuments_docid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.confidentialdocuments_docid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.confidentialdocuments_docid_seq OWNER TO postgres;

--
-- Name: confidentialdocuments_docid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.confidentialdocuments_docid_seq OWNED BY public.confidentialdocuments.docid;


--
-- Name: departments; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.departments (
    department_id integer NOT NULL,
    department_name character varying(100) NOT NULL,
    description text,
    manager_id integer
);


ALTER TABLE public.departments OWNER TO postgres;

--
-- Name: departments_department_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.departments_department_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.departments_department_id_seq OWNER TO postgres;

--
-- Name: departments_department_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.departments_department_id_seq OWNED BY public.departments.department_id;


--
-- Name: employee_roles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.employee_roles (
    employee_role_id integer NOT NULL,
    employee_id integer NOT NULL,
    role_id integer NOT NULL,
    assigned_date timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    assigned_by integer,
    is_active boolean DEFAULT true
);


ALTER TABLE public.employee_roles OWNER TO postgres;

--
-- Name: employee_roles_employee_role_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.employee_roles_employee_role_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.employee_roles_employee_role_id_seq OWNER TO postgres;

--
-- Name: employee_roles_employee_role_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.employee_roles_employee_role_id_seq OWNED BY public.employee_roles.employee_role_id;


--
-- Name: employeeaccess; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.employeeaccess (
    accessid integer NOT NULL,
    employeeid integer NOT NULL,
    systemlogin character varying(50) NOT NULL,
    issuedate date DEFAULT CURRENT_DATE NOT NULL,
    isactive boolean DEFAULT true,
    passwordhash character varying(255),
    passwordchangeddate timestamp without time zone DEFAULT now(),
    passwordcompliant boolean DEFAULT false,
    forcepasswordchange boolean DEFAULT true,
    systemlogin_encrypted bytea
);


ALTER TABLE public.employeeaccess OWNER TO postgres;

--
-- Name: employeeaccess_accessid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.employeeaccess_accessid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.employeeaccess_accessid_seq OWNER TO postgres;

--
-- Name: employeeaccess_accessid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.employeeaccess_accessid_seq OWNED BY public.employeeaccess.accessid;


--
-- Name: employees; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.employees (
    employeeid integer NOT NULL,
    fullname character varying(100) NOT NULL,
    "position" character varying(50) NOT NULL,
    phone character varying(20),
    email character varying(100),
    department_id integer NOT NULL,
    hiredate date DEFAULT CURRENT_DATE,
    salary numeric(10,2),
    phone_encrypted bytea,
    email_encrypted bytea,
    CONSTRAINT employees_salary_check CHECK ((salary >= (0)::numeric))
);


ALTER TABLE public.employees OWNER TO postgres;

--
-- Name: employees_employeeid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.employees_employeeid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.employees_employeeid_seq OWNER TO postgres;

--
-- Name: employees_employeeid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.employees_employeeid_seq OWNED BY public.employees.employeeid;


--
-- Name: encrypted_data_access_log; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.encrypted_data_access_log (
    access_id integer NOT NULL,
    access_time timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    user_name character varying(100) NOT NULL,
    table_name character varying(100) NOT NULL,
    action_type character varying(50) NOT NULL,
    record_id integer,
    decrypted_field character varying(100)
);


ALTER TABLE public.encrypted_data_access_log OWNER TO postgres;

--
-- Name: encrypted_data_access_log_access_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.encrypted_data_access_log_access_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.encrypted_data_access_log_access_id_seq OWNER TO postgres;

--
-- Name: encrypted_data_access_log_access_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.encrypted_data_access_log_access_id_seq OWNED BY public.encrypted_data_access_log.access_id;


--
-- Name: encryption_keys; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.encryption_keys (
    key_id integer NOT NULL,
    key_name character varying(100) NOT NULL,
    key_value text NOT NULL,
    key_version integer DEFAULT 1,
    key_type character varying(50) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100) DEFAULT CURRENT_USER,
    is_active boolean DEFAULT true
);


ALTER TABLE public.encryption_keys OWNER TO postgres;

--
-- Name: encryption_keys_key_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.encryption_keys_key_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.encryption_keys_key_id_seq OWNER TO postgres;

--
-- Name: encryption_keys_key_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.encryption_keys_key_id_seq OWNED BY public.encryption_keys.key_id;


--
-- Name: makes; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.makes (
    makeid integer NOT NULL,
    makename character varying(100) NOT NULL
);


ALTER TABLE public.makes OWNER TO postgres;

--
-- Name: makes_makeid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.makes_makeid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.makes_makeid_seq OWNER TO postgres;

--
-- Name: makes_makeid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.makes_makeid_seq OWNED BY public.makes.makeid;


--
-- Name: models; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.models (
    modelid integer NOT NULL,
    makeid integer NOT NULL,
    modelname character varying(100) NOT NULL
);


ALTER TABLE public.models OWNER TO postgres;

--
-- Name: models_modelid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.models_modelid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.models_modelid_seq OWNER TO postgres;

--
-- Name: models_modelid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.models_modelid_seq OWNED BY public.models.modelid;


--
-- Name: orders; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.orders (
    orderid integer NOT NULL,
    carid integer NOT NULL,
    employeeid integer NOT NULL,
    orderdate date NOT NULL,
    status character varying(50),
    totalamount numeric(10,2)
);


ALTER TABLE public.orders OWNER TO postgres;

--
-- Name: orders_orderid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.orders_orderid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.orders_orderid_seq OWNER TO postgres;

--
-- Name: orders_orderid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.orders_orderid_seq OWNED BY public.orders.orderid;


--
-- Name: orderservices; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.orderservices (
    orderserviceid integer NOT NULL,
    orderid integer NOT NULL,
    serviceid integer NOT NULL
);


ALTER TABLE public.orderservices OWNER TO postgres;

--
-- Name: orderservices_orderserviceid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.orderservices_orderserviceid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.orderservices_orderserviceid_seq OWNER TO postgres;

--
-- Name: orderservices_orderserviceid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.orderservices_orderserviceid_seq OWNED BY public.orderservices.orderserviceid;


--
-- Name: password_history; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.password_history (
    history_id integer NOT NULL,
    employee_id integer NOT NULL,
    password_hash character varying(255) NOT NULL,
    change_date timestamp without time zone DEFAULT now(),
    changed_by integer
);


ALTER TABLE public.password_history OWNER TO postgres;

--
-- Name: password_history_history_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.password_history_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.password_history_history_id_seq OWNER TO postgres;

--
-- Name: password_history_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.password_history_history_id_seq OWNED BY public.password_history.history_id;


--
-- Name: permissions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.permissions (
    permission_id integer NOT NULL,
    permission_name character varying(100) NOT NULL,
    description text,
    object_type character varying(50),
    object_name character varying(100),
    action character varying(20)
);


ALTER TABLE public.permissions OWNER TO postgres;

--
-- Name: permissions_permission_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.permissions_permission_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.permissions_permission_id_seq OWNER TO postgres;

--
-- Name: permissions_permission_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.permissions_permission_id_seq OWNED BY public.permissions.permission_id;


--
-- Name: role_permissions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.role_permissions (
    role_permission_id integer NOT NULL,
    role_id integer NOT NULL,
    permission_id integer NOT NULL,
    granted_date timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    granted_by integer
);


ALTER TABLE public.role_permissions OWNER TO postgres;

--
-- Name: role_permissions_role_permission_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.role_permissions_role_permission_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.role_permissions_role_permission_id_seq OWNER TO postgres;

--
-- Name: role_permissions_role_permission_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.role_permissions_role_permission_id_seq OWNED BY public.role_permissions.role_permission_id;


--
-- Name: roles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.roles (
    role_id integer NOT NULL,
    role_name character varying(50) NOT NULL,
    description text,
    created_date timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.roles OWNER TO postgres;

--
-- Name: roles_role_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.roles_role_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.roles_role_id_seq OWNER TO postgres;

--
-- Name: roles_role_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.roles_role_id_seq OWNED BY public.roles.role_id;


--
-- Name: servicecategories; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.servicecategories (
    categoryid integer NOT NULL,
    categoryname character varying(50) NOT NULL,
    description text
);


ALTER TABLE public.servicecategories OWNER TO postgres;

--
-- Name: servicecategories_categoryid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.servicecategories_categoryid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.servicecategories_categoryid_seq OWNER TO postgres;

--
-- Name: servicecategories_categoryid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.servicecategories_categoryid_seq OWNED BY public.servicecategories.categoryid;


--
-- Name: services; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.services (
    serviceid integer NOT NULL,
    servicename character varying(100) NOT NULL,
    description text,
    price numeric(10,2) NOT NULL,
    durationminutes integer NOT NULL,
    categoryid integer NOT NULL,
    CONSTRAINT services_durationminutes_check CHECK ((durationminutes > 0)),
    CONSTRAINT services_price_check CHECK ((price >= (0)::numeric))
);


ALTER TABLE public.services OWNER TO postgres;

--
-- Name: services_serviceid_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.services_serviceid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.services_serviceid_seq OWNER TO postgres;

--
-- Name: services_serviceid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.services_serviceid_seq OWNED BY public.services.serviceid;


--
-- Name: v_cars; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_cars AS
 SELECT c.carid,
    cl.fullname AS "Владелец",
    mk.makename AS "Марка",
    md.modelname AS "Модель",
    c.year AS "Год выпуска",
    c.vin AS "VIN",
    c.licenseplate AS "Госномер",
    c.color AS "Цвет"
   FROM (((public.cars c
     JOIN public.clients cl ON ((cl.clientid = c.clientid)))
     JOIN public.models md ON ((md.modelid = c.modelid)))
     JOIN public.makes mk ON ((mk.makeid = md.makeid)));


ALTER VIEW public.v_cars OWNER TO postgres;

--
-- Name: v_clients; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_clients AS
 SELECT clientid,
    fullname AS "ФИО клиента",
    phone AS "Телефон",
    email AS "Почта",
    address AS "Адрес",
    registrationdate AS "Дата регистрации"
   FROM public.clients;


ALTER VIEW public.v_clients OWNER TO postgres;

--
-- Name: v_confidential_documents; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_confidential_documents AS
 SELECT d.docid,
    d.doctitle AS "Название документа",
    e.fullname AS "Создатель",
    dep.department_name AS "Отдел",
    d.createddate AS "Дата создания",
    d.accesslevel AS "Уровень доступа",
    d.content AS "Содержание"
   FROM ((public.confidentialdocuments d
     JOIN public.employees e ON ((e.employeeid = d.creatorid)))
     JOIN public.departments dep ON ((dep.department_id = d.department_id)));


ALTER VIEW public.v_confidential_documents OWNER TO postgres;

--
-- Name: v_confidential_documents_secure; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_confidential_documents_secure WITH (security_invoker='true') AS
 SELECT cd.docid,
    cd.doctitle AS "Название документа",
    e.fullname AS "Создатель",
    d.department_name AS "Отдел",
    cd.createddate AS "Дата создания",
    cd.accesslevel AS "Уровень доступа",
    cd.content AS "Содержание"
   FROM ((public.confidentialdocuments cd
     JOIN public.employees e ON ((e.employeeid = cd.creatorid)))
     JOIN public.departments d ON ((d.department_id = cd.department_id)));


ALTER VIEW public.v_confidential_documents_secure OWNER TO postgres;

--
-- Name: v_departments; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_departments AS
 SELECT d.department_id,
    d.department_name AS "Отдел",
    e.fullname AS "Руководитель",
    d.description AS "Описание"
   FROM (public.departments d
     LEFT JOIN public.employees e ON ((e.employeeid = d.manager_id)));


ALTER VIEW public.v_departments OWNER TO postgres;

--
-- Name: v_employee_access; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_employee_access AS
 SELECT a.accessid,
    e.fullname AS "Сотрудник",
    a.systemlogin AS "Логин",
    a.issuedate AS "Дата выдачи",
    a.isactive AS "Активен"
   FROM (public.employeeaccess a
     JOIN public.employees e ON ((e.employeeid = a.employeeid)));


ALTER VIEW public.v_employee_access OWNER TO postgres;

--
-- Name: v_employees; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_employees AS
 SELECT e.employeeid,
    e.fullname AS "ФИО сотрудника",
    e."position" AS "Должность",
    e.phone AS "Телефон",
    e.email AS "Почта",
    d.department_name AS "Отдел",
    e.hiredate AS "Дата найма",
    e.salary AS "Оклад",
    a.systemlogin AS "Логин",
    a.isactive AS "Активен"
   FROM ((public.employees e
     LEFT JOIN public.employeeaccess a ON ((a.employeeid = e.employeeid)))
     LEFT JOIN public.departments d ON ((d.department_id = e.department_id)));


ALTER VIEW public.v_employees OWNER TO postgres;

--
-- Name: v_hr_employees; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_hr_employees AS
 SELECT e.employeeid,
    e.fullname AS "ФИО сотрудника",
    e."position" AS "Должность",
    public.apply_data_masking(e.phone_encrypted, 'phone'::character varying, e.employeeid) AS "Телефон",
    public.apply_data_masking(e.email_encrypted, 'email'::character varying, e.employeeid) AS "Email",
    d.department_name AS "Отдел",
    e.hiredate AS "Дата найма",
    e.salary AS "Оклад"
   FROM (public.employees e
     LEFT JOIN public.departments d ON ((d.department_id = e.department_id)));


ALTER VIEW public.v_hr_employees OWNER TO postgres;

--
-- Name: v_makes; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_makes AS
 SELECT makeid,
    makename AS "Марка"
   FROM public.makes;


ALTER VIEW public.v_makes OWNER TO postgres;

--
-- Name: v_models; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_models AS
 SELECT m.modelid,
    mk.makename AS "Марка",
    m.modelname AS "Модель"
   FROM (public.models m
     JOIN public.makes mk ON ((m.makeid = mk.makeid)));


ALTER VIEW public.v_models OWNER TO postgres;

--
-- Name: v_order_services; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_order_services AS
 SELECT os.orderserviceid,
    o.orderid AS "№ Заказа",
    s.servicename AS "Услуга"
   FROM ((public.orderservices os
     JOIN public.orders o ON ((os.orderid = o.orderid)))
     JOIN public.services s ON ((os.serviceid = s.serviceid)));


ALTER VIEW public.v_order_services OWNER TO postgres;

--
-- Name: v_orders; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_orders AS
 SELECT o.orderid,
    cl.fullname AS "Клиент",
    concat(mk.makename, ' ', md.modelname, ' (', c.vin, ')') AS "Автомобиль",
    e.fullname AS "Ответственный сотрудник",
    o.orderdate AS "Дата заказа",
    o.status AS "Статус",
    o.totalamount AS "Сумма"
   FROM (((((public.orders o
     JOIN public.cars c ON ((o.carid = c.carid)))
     JOIN public.models md ON ((c.modelid = md.modelid)))
     JOIN public.makes mk ON ((md.makeid = mk.makeid)))
     JOIN public.clients cl ON ((c.clientid = cl.clientid)))
     JOIN public.employees e ON ((e.employeeid = o.employeeid)));


ALTER VIEW public.v_orders OWNER TO postgres;

--
-- Name: v_public_employees; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_public_employees AS
 SELECT e.employeeid,
    e.fullname AS "ФИО сотрудника",
    e."position" AS "Должность",
    public.apply_data_masking(e.phone_encrypted, 'phone'::character varying, e.employeeid) AS "Телефон",
    public.apply_data_masking(e.email_encrypted, 'email'::character varying, e.employeeid) AS "Email",
    d.department_name AS "Отдел"
   FROM (public.employees e
     LEFT JOIN public.departments d ON ((d.department_id = e.department_id)));


ALTER VIEW public.v_public_employees OWNER TO postgres;

--
-- Name: v_secure_clients; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_secure_clients AS
 SELECT clientid,
    fullname AS "ФИО клиента",
    public.apply_data_masking(phone_encrypted, 'phone'::character varying) AS "Телефон",
    public.apply_data_masking(email_encrypted, 'email'::character varying) AS "Email",
    public.apply_data_masking(address_encrypted, 'address'::character varying) AS "Адрес",
    registrationdate AS "Дата регистрации"
   FROM public.clients c;


ALTER VIEW public.v_secure_clients OWNER TO postgres;

--
-- Name: v_secure_documents; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_secure_documents AS
 SELECT cd.docid,
    cd.doctitle AS "Название документа",
    e.fullname AS "Создатель",
    d.department_name AS "Отдел",
    cd.createddate AS "Дата создания",
    cd.accesslevel AS "Уровень доступа",
        CASE
            WHEN (EXISTS ( SELECT 1
               FROM ((pg_roles r
                 JOIN pg_auth_members m ON ((r.oid = m.roleid)))
                 JOIN pg_roles u ON ((u.oid = m.member)))
              WHERE ((u.rolname = CURRENT_USER) AND (r.rolname = ANY (ARRAY['security_officer'::name, 'superadmin'::name]))))) THEN public.decrypt_data(cd.content_encrypted, 'document'::character varying)
            WHEN ((cd.accesslevel)::text = 'Public'::text) THEN public.decrypt_data(cd.content_encrypted, 'document'::character varying)
            ELSE '*** CONTENT REQUIRES AUTHORIZATION ***'::text
        END AS "Содержание"
   FROM ((public.confidentialdocuments cd
     JOIN public.employees e ON ((e.employeeid = cd.creatorid)))
     JOIN public.departments d ON ((d.department_id = cd.department_id)));


ALTER VIEW public.v_secure_documents OWNER TO postgres;

--
-- Name: v_security_audit_log; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_security_audit_log AS
 SELECT audit_id,
    table_name AS "таблица",
        CASE
            WHEN ((action_type)::text = 'INSERT'::text) THEN 'Добавление'::character varying
            WHEN ((action_type)::text = 'UPDATE'::text) THEN 'Обновление'::character varying
            WHEN ((action_type)::text = 'DELETE'::text) THEN 'Удаление'::character varying
            ELSE action_type
        END AS "действие",
    user_name AS "пользователь",
    action_timestamp AS "время_действия",
    old_data AS "старые_данные",
    new_data AS "новые_данные",
    ip_address AS "ip_адрес"
   FROM public.audit_log;


ALTER VIEW public.v_security_audit_log OWNER TO postgres;

--
-- Name: v_security_employee_access; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_security_employee_access AS
 SELECT ea.accessid,
    e.fullname AS employee_name,
    ea.systemlogin,
    ea.issuedate,
        CASE
            WHEN ea.isactive THEN 'Активен'::text
            ELSE 'Неактивен'::text
        END AS access_status,
    ea.passwordchangeddate,
        CASE
            WHEN ea.passwordcompliant THEN 'Соответствует'::text
            ELSE 'Не соответствует'::text
        END AS password_compliance,
        CASE
            WHEN ea.forcepasswordchange THEN 'Требуется'::text
            ELSE 'Не требуется'::text
        END AS force_password_change
   FROM (public.employeeaccess ea
     LEFT JOIN public.employees e ON ((ea.employeeid = e.employeeid)));


ALTER VIEW public.v_security_employee_access OWNER TO postgres;

--
-- Name: v_security_employee_roles; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_security_employee_roles AS
 SELECT er.employee_role_id,
    e.fullname AS employee_name,
    r.role_name,
    er.assigned_date,
    assigner.fullname AS assigned_by_name,
        CASE
            WHEN er.is_active THEN 'Активна'::text
            ELSE 'Неактивна'::text
        END AS role_status
   FROM (((public.employee_roles er
     LEFT JOIN public.employees e ON ((er.employee_id = e.employeeid)))
     LEFT JOIN public.roles r ON ((er.role_id = r.role_id)))
     LEFT JOIN public.employees assigner ON ((er.assigned_by = assigner.employeeid)));


ALTER VIEW public.v_security_employee_roles OWNER TO postgres;

--
-- Name: v_security_employees; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_security_employees AS
 SELECT e.employeeid,
    e.fullname AS "ФИО сотрудника",
    e."position" AS "Должность",
    public.apply_data_masking(e.phone_encrypted, 'phone'::character varying, e.employeeid) AS "Телефон",
    public.apply_data_masking(e.email_encrypted, 'email'::character varying, e.employeeid) AS "Email",
    d.department_name AS "Отдел",
    ea.systemlogin AS "Логин системы",
    ea.isactive AS "Активен"
   FROM ((public.employees e
     LEFT JOIN public.departments d ON ((d.department_id = e.department_id)))
     LEFT JOIN public.employeeaccess ea ON ((ea.employeeid = e.employeeid)));


ALTER VIEW public.v_security_employees OWNER TO postgres;

--
-- Name: v_security_encrypted_access_log; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_security_encrypted_access_log AS
 SELECT access_id,
    access_time AS "время_доступа",
    user_name AS "пользователь",
    table_name AS "таблица",
    action_type AS "тип_действия",
    record_id AS "id_записи",
    decrypted_field AS "расшифрованное_поле"
   FROM public.encrypted_data_access_log;


ALTER VIEW public.v_security_encrypted_access_log OWNER TO postgres;

--
-- Name: v_security_password_history; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_security_password_history AS
 SELECT ph.history_id,
    e.fullname AS employee_name,
    ph.password_hash,
    ph.change_date,
    changer.fullname AS changed_by_name,
    ph.changed_by
   FROM ((public.password_history ph
     LEFT JOIN public.employees e ON ((ph.employee_id = e.employeeid)))
     LEFT JOIN public.employees changer ON ((ph.changed_by = changer.employeeid)));


ALTER VIEW public.v_security_password_history OWNER TO postgres;

--
-- Name: v_security_password_history2; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_security_password_history2 AS
 SELECT ph.history_id,
    ph.employee_id,
    e.fullname AS "ФИО сотрудника",
    ph.change_date AS "Дата изменения",
        CASE
            WHEN (EXISTS ( SELECT 1
               FROM ((pg_roles r
                 JOIN pg_auth_members m ON ((r.oid = m.roleid)))
                 JOIN pg_roles u ON ((u.oid = m.member)))
              WHERE ((u.rolname = CURRENT_USER) AND (r.rolname = 'superadmin'::name)))) THEN ph.password_hash
            ELSE '*** MASKED ***'::character varying
        END AS "Хэш пароля",
    ph.changed_by AS "Изменено пользователем"
   FROM (public.password_history ph
     JOIN public.employees e ON ((e.employeeid = ph.employee_id)))
  ORDER BY ph.change_date DESC;


ALTER VIEW public.v_security_password_history2 OWNER TO postgres;

--
-- Name: v_security_permissions; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_security_permissions AS
 SELECT permission_id,
    permission_name,
    description,
    object_type AS "тип_объекта",
    object_name AS "имя_объекта",
    action AS "действие"
   FROM public.permissions;


ALTER VIEW public.v_security_permissions OWNER TO postgres;

--
-- Name: v_security_role_permissions; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_security_role_permissions AS
 SELECT rp.role_permission_id,
    r.role_name,
    p.permission_name,
    p.description AS permission_description,
    p.object_type,
    p.object_name,
    p.action,
    rp.granted_date,
    granter.fullname AS granted_by_name
   FROM (((public.role_permissions rp
     LEFT JOIN public.roles r ON ((rp.role_id = r.role_id)))
     LEFT JOIN public.permissions p ON ((rp.permission_id = p.permission_id)))
     LEFT JOIN public.employees granter ON ((rp.granted_by = granter.employeeid)));


ALTER VIEW public.v_security_role_permissions OWNER TO postgres;

--
-- Name: v_security_roles; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_security_roles AS
 SELECT role_id,
    role_name,
    description,
    created_date
   FROM public.roles;


ALTER VIEW public.v_security_roles OWNER TO postgres;

--
-- Name: v_service_categories; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_service_categories AS
 SELECT categoryid,
    categoryname AS "Категория услуги",
    description AS "Описание"
   FROM public.servicecategories;


ALTER VIEW public.v_service_categories OWNER TO postgres;

--
-- Name: v_services; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_services AS
 SELECT s.serviceid,
    s.servicename AS "Услуга",
    c.categoryname AS "Категория",
    s.price AS "Цена",
    s.durationminutes AS "Длительность (мин)"
   FROM (public.services s
     JOIN public.servicecategories c ON ((c.categoryid = s.categoryid)));


ALTER VIEW public.v_services OWNER TO postgres;

--
-- Name: audit_log audit_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.audit_log ALTER COLUMN audit_id SET DEFAULT nextval('public.audit_log_audit_id_seq'::regclass);


--
-- Name: cars carid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cars ALTER COLUMN carid SET DEFAULT nextval('public.cars_carid_seq'::regclass);


--
-- Name: clients clientid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.clients ALTER COLUMN clientid SET DEFAULT nextval('public.clients_clientid_seq'::regclass);


--
-- Name: confidentialdocuments docid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.confidentialdocuments ALTER COLUMN docid SET DEFAULT nextval('public.confidentialdocuments_docid_seq'::regclass);


--
-- Name: departments department_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.departments ALTER COLUMN department_id SET DEFAULT nextval('public.departments_department_id_seq'::regclass);


--
-- Name: employee_roles employee_role_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employee_roles ALTER COLUMN employee_role_id SET DEFAULT nextval('public.employee_roles_employee_role_id_seq'::regclass);


--
-- Name: employeeaccess accessid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employeeaccess ALTER COLUMN accessid SET DEFAULT nextval('public.employeeaccess_accessid_seq'::regclass);


--
-- Name: employees employeeid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employees ALTER COLUMN employeeid SET DEFAULT nextval('public.employees_employeeid_seq'::regclass);


--
-- Name: encrypted_data_access_log access_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.encrypted_data_access_log ALTER COLUMN access_id SET DEFAULT nextval('public.encrypted_data_access_log_access_id_seq'::regclass);


--
-- Name: encryption_keys key_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.encryption_keys ALTER COLUMN key_id SET DEFAULT nextval('public.encryption_keys_key_id_seq'::regclass);


--
-- Name: makes makeid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.makes ALTER COLUMN makeid SET DEFAULT nextval('public.makes_makeid_seq'::regclass);


--
-- Name: models modelid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.models ALTER COLUMN modelid SET DEFAULT nextval('public.models_modelid_seq'::regclass);


--
-- Name: orders orderid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orders ALTER COLUMN orderid SET DEFAULT nextval('public.orders_orderid_seq'::regclass);


--
-- Name: orderservices orderserviceid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orderservices ALTER COLUMN orderserviceid SET DEFAULT nextval('public.orderservices_orderserviceid_seq'::regclass);


--
-- Name: password_history history_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.password_history ALTER COLUMN history_id SET DEFAULT nextval('public.password_history_history_id_seq'::regclass);


--
-- Name: permissions permission_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.permissions ALTER COLUMN permission_id SET DEFAULT nextval('public.permissions_permission_id_seq'::regclass);


--
-- Name: role_permissions role_permission_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.role_permissions ALTER COLUMN role_permission_id SET DEFAULT nextval('public.role_permissions_role_permission_id_seq'::regclass);


--
-- Name: roles role_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles ALTER COLUMN role_id SET DEFAULT nextval('public.roles_role_id_seq'::regclass);


--
-- Name: servicecategories categoryid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.servicecategories ALTER COLUMN categoryid SET DEFAULT nextval('public.servicecategories_categoryid_seq'::regclass);


--
-- Name: services serviceid; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.services ALTER COLUMN serviceid SET DEFAULT nextval('public.services_serviceid_seq'::regclass);


--
-- Data for Name: audit_log; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.audit_log VALUES (1, 'Clients', 'INSERT', 'e_volkova', '2025-11-12 19:29:48.08497', NULL, '{"Email": "ss@gmail.com", "Phone": "+72218767712", "Address": "Широтная, 123", "FullName": "Пупкин Дмитрий", "RegistrationDate": "2025-11-11"}', NULL);
INSERT INTO public.audit_log VALUES (2, 'Employees', 'INSERT', 'e_volkova', '2025-11-12 21:03:35.343989', NULL, '{"Email": "ssg@gmail.com", "Phone": "+72218767712", "Salary": 30000, "FullName": "Вовчик Кривой", "HireDate": "2025-11-12", "Position": "механик", "department_id": 3}', NULL);
INSERT INTO public.audit_log VALUES (3, 'Employees', 'INSERT', 'e_volkova', '2025-11-12 21:04:01.17394', NULL, '{"Email": "ssg@gmail.com", "Phone": "+72218767712", "Salary": 30000, "FullName": "Вовчик Кривой", "HireDate": "2025-11-12", "Position": "механик", "department_id": 3}', NULL);
INSERT INTO public.audit_log VALUES (4, 'Employees', 'DELETE', 'e_volkova', '2025-11-12 21:08:55.549213', '{"EmployeeID": 8}', NULL, NULL);
INSERT INTO public.audit_log VALUES (5, 'Clients', 'INSERT', 'e_volkova', '2025-11-13 12:45:35.985189', NULL, '{"Email": "ssg@gmail.com", "Phone": "+72218767712", "Address": "Широтная, 123", "FullName": "аоыфоа", "RegistrationDate": "2025-11-11"}', NULL);
INSERT INTO public.audit_log VALUES (6, 'Clients', 'DELETE', 'e_volkova', '2025-11-13 12:45:46.123859', '{"ClientID": 9}', NULL, NULL);
INSERT INTO public.audit_log VALUES (7, 'Clients', 'UPDATE', 'e_volkova', '2025-11-13 13:03:42.335804', NULL, '{"Email": "ivanov@mail.ru", "Phone": "+79995551112", "Address": "Москва, ул. Ленина, д.10", "ClientID": 1, "FullName": "Сергей Иванов", "RegistrationDate": "2023-03-10"}', NULL);
INSERT INTO public.audit_log VALUES (8, 'Employees', 'UPDATE', 'e_volkova', '2025-11-13 13:22:18.875142', NULL, '{"Email": "ssg@gmail.com", "Phone": "+72218767712", "Salary": 30000.0, "FullName": "Вовачик Кривой", "HireDate": "2025-11-12", "Position": "механик", "EmployeeID": 9, "department_id": 3}', NULL);
INSERT INTO public.audit_log VALUES (9, 'Clients', 'UPDATE', 'e_volkova', '2025-11-16 23:56:39.164871', NULL, '{"Email": "petova@mail.ru", "Phone": "+79995552222", "Address": "Москва, пр. Мира, д.25", "ClientID": 2, "FullName": "Мария Петрова", "RegistrationDate": "2023-05-18"}', NULL);
INSERT INTO public.audit_log VALUES (10, 'Makes', 'INSERT', 'e_volkova', '2025-11-17 11:43:55.283024', NULL, '{"MakeName": "Haval"}', NULL);
INSERT INTO public.audit_log VALUES (11, 'Makes', 'UPDATE', 'e_volkova', '2025-11-17 11:44:12.608371', NULL, '{"MakeID": 6, "MakeName": "Havall"}', NULL);
INSERT INTO public.audit_log VALUES (12, 'Cars', 'UPDATE', 'e_volkova', '2025-11-17 12:29:38.119267', '{"CarID": 2}', '{"VIN": "JTDEPMAEXL3000022"}', NULL);
INSERT INTO public.audit_log VALUES (13, 'Cars', 'INSERT', 'e_volkova', '2025-11-17 12:43:27.913316', NULL, '{"VIN": "WVWZZZAUZKW78901221"}', NULL);
INSERT INTO public.audit_log VALUES (14, 'Cars', 'DELETE', 'e_volkova', '2025-11-17 12:43:56.873607', '{"CarID": 6}', NULL, NULL);
INSERT INTO public.audit_log VALUES (15, 'Services', 'INSERT', 'e_volkova', '2025-11-17 14:31:25.278114', NULL, '{"ServiceName": "Замена колодок "}', NULL);
INSERT INTO public.audit_log VALUES (16, 'Services', 'UPDATE', 'e_volkova', '2025-11-17 14:31:53.876901', NULL, '{"ServiceID": 7}', NULL);
INSERT INTO public.audit_log VALUES (17, 'ServiceCategories', 'INSERT', 'e_volkova', '2025-11-17 14:37:30.983625', NULL, '{"CategoryName": "Кузовной ремонт"}', NULL);
INSERT INTO public.audit_log VALUES (18, 'ServiceCategories', 'INSERT', 'e_volkova', '2025-11-17 14:42:56.060366', NULL, '{"CategoryName": "Электрика"}', NULL);
INSERT INTO public.audit_log VALUES (19, 'ServiceCategories', 'UPDATE', 'e_volkova', '2025-11-17 14:43:06.723729', NULL, '{"CategoryID": 7, "CategoryName": "Электрика"}', NULL);
INSERT INTO public.audit_log VALUES (20, 'Models', 'INSERT', 'e_volkova', '2025-11-17 14:47:13.93388', NULL, '{"MakeID": 5, "ModelName": "Focus"}', NULL);
INSERT INTO public.audit_log VALUES (21, 'Models', 'UPDATE', 'e_volkova', '2025-11-17 14:55:43.642215', NULL, '{"MakeID": 2, "ModelID": 3, "ModelName": "X6"}', NULL);
INSERT INTO public.audit_log VALUES (22, 'Orders', 'INSERT', 'e_volkova', '2025-11-17 15:18:58.686894', NULL, '{"CarID": 2, "Status": "В процессе ", "OrderDate": "2025-02-02", "EmployeeID": 9}', NULL);
INSERT INTO public.audit_log VALUES (23, 'Orders', 'UPDATE', 'e_volkova', '2025-11-17 15:19:25.209295', NULL, '{"CarID": 2, "Status": "В процессе ", "OrderID": 6, "OrderDate": "2025-02-02", "EmployeeID": 1}', NULL);
INSERT INTO public.audit_log VALUES (24, 'OrderServices', 'INSERT', 'e_volkova', '2025-11-17 15:19:48.789599', NULL, '{"OrderID": 6, "ServiceID": 3}', NULL);
INSERT INTO public.audit_log VALUES (25, 'Cars', 'INSERT', 'e_volkova', '2025-11-17 19:33:53.214155', NULL, '{"VIN": "WVWZZZAUZKW78901221"}', NULL);
INSERT INTO public.audit_log VALUES (26, 'Cars', 'UPDATE', 'e_volkova', '2025-11-17 19:34:07.786702', '{"CarID": 8}', '{"VIN": "WVWZZZAUZKW78901221"}', NULL);
INSERT INTO public.audit_log VALUES (27, 'Orders', 'UPDATE', 'a_smirnov', '2025-11-17 21:55:52.934611', NULL, '{"Status": "Выполнен", "OrderID": 5}', NULL);
INSERT INTO public.audit_log VALUES (28, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-18 23:44:35.354565', NULL, '{"accessid": 2, "isactive": true, "employeeid": 2, "systemlogin": "e.volokova", "passwordcompliant": false, "forcepasswordchange": true}', NULL);
INSERT INTO public.audit_log VALUES (29, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-18 23:55:39.019818', NULL, '{"accessid": 5, "isactive": false, "employeeid": 5, "systemlogin": "m.danilov", "passwordcompliant": true, "forcepasswordchange": true}', NULL);
INSERT INTO public.audit_log VALUES (30, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-18 23:56:06.753272', NULL, '{"accessid": 5, "isactive": true, "employeeid": 5, "systemlogin": "m.danilov", "passwordcompliant": true, "forcepasswordchange": true}', NULL);
INSERT INTO public.audit_log VALUES (31, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-19 21:52:50.681387', NULL, '{"accessid": 4, "isactive": true, "employeeid": 4, "systemlogin": "t_grigoreva", "passwordcompliant": true, "forcepasswordchange": true}', NULL);
INSERT INTO public.audit_log VALUES (32, 'employee_roles', 'INSERT', 'm_danilov', '2025-11-19 21:59:57.289953', NULL, '{"role_id": 4, "is_active": true, "assigned_by": 5, "employee_id": 10}', NULL);
INSERT INTO public.audit_log VALUES (33, 'employee_roles', 'UPDATE', 'm_danilov', '2025-11-19 22:10:43.107525', NULL, '{"role_id": 2, "is_active": true, "employee_id": 10, "employee_role_id": 6}', NULL);
INSERT INTO public.audit_log VALUES (34, 'confidentialdocuments', 'INSERT', 'z_starkov', '2025-11-19 23:32:01.195258', NULL, '{"content": "доходы расходы +500 миллионов рублей", "doctitle": "Отчет за 2025 год", "creatorid": 6, "accesslevel": "Strictly", "createddate": "2025-11-01", "department_id": 1}', NULL);
INSERT INTO public.audit_log VALUES (35, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-20 11:57:08.978037', NULL, '{"accessid": 6, "isactive": true, "employeeid": 6, "systemlogin": "z_starkov", "passwordcompliant": true, "forcepasswordchange": true}', NULL);
INSERT INTO public.audit_log VALUES (36, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-20 11:57:18.056419', NULL, '{"accessid": 5, "isactive": true, "employeeid": 5, "systemlogin": "m_danilov", "passwordcompliant": true, "forcepasswordchange": true}', NULL);
INSERT INTO public.audit_log VALUES (37, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-20 11:57:28.010256', NULL, '{"accessid": 3, "isactive": true, "employeeid": 3, "systemlogin": "i_fedorov", "passwordcompliant": true, "forcepasswordchange": true}', NULL);
INSERT INTO public.audit_log VALUES (38, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-20 11:57:37.752019', NULL, '{"accessid": 2, "isactive": true, "employeeid": 2, "systemlogin": "e_volokova", "passwordcompliant": true, "forcepasswordchange": true}', NULL);
INSERT INTO public.audit_log VALUES (39, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-20 11:57:45.487309', NULL, '{"accessid": 1, "isactive": true, "employeeid": 1, "systemlogin": "a_smirnov", "passwordcompliant": true, "forcepasswordchange": true}', NULL);
INSERT INTO public.audit_log VALUES (40, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-22 09:40:51.719507', NULL, '{"accessid": 1, "isactive": true, "employeeid": 1, "systemlogin": "a_smirnov", "passwordcompliant": true, "forcepasswordchange": false}', NULL);
INSERT INTO public.audit_log VALUES (41, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-22 09:41:02.022023', NULL, '{"accessid": 2, "isactive": true, "employeeid": 2, "systemlogin": "e_volokova", "passwordcompliant": true, "forcepasswordchange": false}', NULL);
INSERT INTO public.audit_log VALUES (42, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-22 09:41:07.957296', NULL, '{"accessid": 3, "isactive": true, "employeeid": 3, "systemlogin": "i_fedorov", "passwordcompliant": true, "forcepasswordchange": false}', NULL);
INSERT INTO public.audit_log VALUES (43, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-22 09:41:17.830724', NULL, '{"accessid": 4, "isactive": true, "employeeid": 4, "systemlogin": "t_grigoreva", "passwordcompliant": true, "forcepasswordchange": false}', NULL);
INSERT INTO public.audit_log VALUES (44, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-22 10:37:18.066725', NULL, '{"accessid": 2, "isactive": true, "employeeid": 2, "systemlogin": "e_volkova", "passwordcompliant": true, "forcepasswordchange": false}', NULL);
INSERT INTO public.audit_log VALUES (45, 'Employees', 'INSERT', 'z_starkov', '2025-11-25 15:26:35.788327', NULL, '{"Email": "ivanov@mail.ru", "Phone": "+7-900-000-00-65", "Salary": 37000.0, "FullName": "Тест2", "HireDate": "2025-11-25", "Position": "менеджер3", "department_id": 4}', NULL);
INSERT INTO public.audit_log VALUES (46, 'employeeaccess', 'INSERT', 'm_danilov', '2025-11-25 15:36:38.533062', NULL, '{"isactive": true, "issuedate": "2025-11-25", "employeeid": 11, "systemlogin": "test_2", "passwordcompliant": false, "forcepasswordchange": true}', NULL);
INSERT INTO public.audit_log VALUES (47, 'employeeaccess', 'UPDATE', 'm_danilov', '2025-11-25 15:40:48.396761', NULL, '{"accessid": 11, "isactive": true, "employeeid": 11, "systemlogin": "test_2", "passwordcompliant": false, "forcepasswordchange": true}', NULL);
INSERT INTO public.audit_log VALUES (48, 'Orders', 'UPDATE', 'a_smirnov', '2025-11-25 15:42:41.102462', NULL, '{"Status": "Ожидает запчасти", "OrderID": 3}', NULL);
INSERT INTO public.audit_log VALUES (49, 'Clients', 'INSERT', 'e_volkova', '2025-11-25 18:14:43.266301', NULL, '{"Email": "ivanov@mail.ru", "Phone": "+7-900-122-52-65", "Address": "Широтная, 123", "FullName": "deduki daimond", "RegistrationDate": "2023-03-10"}', NULL);


--
-- Data for Name: cars; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.cars VALUES (1, 1, 1, 2018, 'JTNB11HK1J3000011', 'А123ВС77', 'Черный');
INSERT INTO public.cars VALUES (3, 3, 3, 2021, 'WBAXX11040L300033', 'С789МТ77', 'Серебристый');
INSERT INTO public.cars VALUES (4, 4, 4, 2019, 'KMHJB81BBJU300044', 'Е321КС77', 'Синий');
INSERT INTO public.cars VALUES (5, 5, 5, 2022, 'WVWZZZ3CZME300055', 'Т654РУ77', 'Красный');
INSERT INTO public.cars VALUES (2, 2, 2, 2022, 'JTDEPMAEXL3000022', 'В456ОР77', 'Белый');
INSERT INTO public.cars VALUES (8, 3, 6, 2011, 'WVWZZZAUZKW78901221', 'В456ОР72', 'Серый');


--
-- Data for Name: clients; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.clients VALUES (3, 'Андрей Соколов', '+79995553333', 'sokolov@mail.ru', 'Москва, ул. Чехова, д.7', '2023-06-01', '\xc30d04090302153b3774374cb4cf6ed23d0125f3571df93d5a86f5581b7cd5314e570a5daba0aa2b50afdff392269c0a9c9f3e019c7ab5f93c909a1b129f1949597f14e93ca59da370ef3014af5f', '\xc30d040903022f23ce65fea4fcbe6ad2400105cf925c2f5e49edcf05a00707e9faeb442239cb4cf55c7587a868536b57da49074fa8c35f40f7b229daa815721cd88b5d9f219f7ef485fb0326aef71a9c64', '\xc30d040903023b2d2c5de4f9c1af78d25701e8a54671bbd63dd5c0f20338f8b9da690a43c7fda4307c02c7fa6019a2e44d17d645ce0172528c8012e24ee6ac515bfa3fca8b84ec62b0ac568b81f4557f97f01aa4f775844f94176844908c04f8b428c8ee3f2dee99');
INSERT INTO public.clients VALUES (4, 'Виктория Кузнецова', '+79995554444', 'kuznetsova@mail.ru', 'Москва, ул. Лесная, д.3', '2023-07-12', '\xc30d040903027d454c006fc404f07bd23d01e9fa5e17685bd4741b74bacc1ad9fcbe687457504630ccf2311bccc8eecc85a8d833efc3e46a2a09c829d102f0326f4fffa60d5eaf3f88dc7729c92b', '\xc30d04090302b21664d7565da7627dd24301ead28158aed1ec90074363f6bd2f150a5b36a49a8d057ada4568b7a7d75de8439eb216d77c99cec2038eb5ca60cd32a618e3a530a93bc1201b14a31fb538b071bb67', '\xc30d0409030269af4c08b4594f9a72d257016a8a11d6166786a42629f09b7a031caa8449e3cce064bf9453d08069a76766420c8a72f825038000d849640fcd9767c97cd5e7b11f040aa69441590b9d2d86b4928dee5e8bd57f8d81bc443d416e5bafb2049697fa23');
INSERT INTO public.clients VALUES (5, 'Дмитрий Попов', '+79995555555', 'popov@mail.ru', 'Москва, ул. Горького, д.15', '2023-08-09', '\xc30d040903026f4a190bd70f083c6fd23d013d554ac3b92b6cd6dbc270dc9d31864963e14380ba2987b105e041eaed70783d6fc018e59f4ec11e396d6ab86a7120ec7b6a68bb727637da26e6d44e', '\xc30d0409030252729ed58e19e2c769d23e014f0d0c6190feadc299976b667592ebf6b95607a2975bd99d8e68ae31a55ab6be194bcf7ce7e2d351abb66495c289a4a7a6a80b6775412e29a476daa027', '\xc30d040903023be6f94975f8fc3a7cd25c018f0e90f202abc12cd07494b48b84702f2ecdc2034884132f557d4eab27e7d22c7092577b290b48c9abc9aa404cc96a66d5a80464e130ad9ca32081d540261a99feb25b371263378fb7c921b2c7e4d50523f9e2a8963862c0e63156');
INSERT INTO public.clients VALUES (8, 'Пупкин Дмитрий', '+72218767712', 'ss@gmail.com', 'Широтная, 123', '2025-11-11', '\xc30d040903020b1e8ce35ee10a8c62d23d019c9cb3b7e5958a3ca89f8bfa9e09e73acef90dfbd467145c7af884b8936cf6228f100002896903469ebf3c541dff3926b98de845acc7f545c79b078e', '\xc30d0409030274c8e86e6a2306fc7cd23d01b92d1128eaa4ec7c4e0fdbc3216dd58bb0d0b0ea312db097fd279e846f45514d840c0de8b382d458212c328da82219f8a36962fc313c3a27f5e62834', '\xc30d04090302dae503092c57e55a78d246014487643dc522a757e1bd2a896735ca4daf237a0475d69251399f4430093c4cc9d10100b18c6714eb4bd7b32042f160c5142134f9d96a855bf81db2452e3c27aa7ba2ae2028');
INSERT INTO public.clients VALUES (1, 'Сергей Иванов', '+79995551112', 'ivanov@mail.ru', 'Москва, ул. Ленина, д.10', '2023-03-10', '\xc30d04090302f22c47dd8613233a7bd23d01737a3487c540e68ddb9136332e66b46bd785feaad6d65659a6989363ffc8e1ffb89ebe2099a4da74eca8d5b4223ea26ff454ad3c2df0c8dba15c2586', '\xc30d0409030291bde6ba3df55b3b7fd23f01a134a1c140d1947d11b2f588a5edcb332ed7e370934703816190cfa912ecc61a81690af81ac0f862fe7576c5369d2fb8c10e10d7357f942bdfa8683ec692', '\xc30d04090302c9cc510749579c8561d258019f8ada952311f724a0144d04cb537dc6b85e82fce9106d44a69910eaef7bba4ebd9bc53965e91d511efa3aaaedac205fae244cdd08fd37d7fc04cbf771794e41edd7de01f181302357e6e9042bb0cd116d226dcde7d0c6');
INSERT INTO public.clients VALUES (2, 'Мария Петрова', '+79995552222', 'petova@mail.ru', 'Москва, пр. Мира, д.25', '2023-05-18', '\xc30d04090302f9cd972d772d9d2d74d23d01755a0a03c199fa7bc75bd8a4347fbe9d05469c2101b8fd624875bc62251249ff668101766d29b270af9176dd472fea3b80ff1552c116a8401586ff25', '\xc30d040903028e87db63a668417368d23f01c306cf8435053cb8006dad28fec41b8a2a0d5e7e1d0095860ba212d1768ceb3909d6b74ff272e15a12e86ac2c460581daf4cedb4bd9f24d0694cb1265fbd', '\xc30d040903022b21cc8735ebb5a977d25401886ffc4b9c40fa5ffe4400d8124d548264a5daa1f793b1d62cdf124797ad82a6086d793fe476884ba4c2f78056eccee46550384be7ce2ba0819f885e617712855ea7183213453e437888831ff88f3d1f52cdfb');
INSERT INTO public.clients VALUES (10, 'deduki daimond', '+7-900-122-52-65', 'ivanov@mail.ru', 'Широтная, 123', '2023-03-10', NULL, NULL, NULL);


--
-- Data for Name: confidentialdocuments; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.confidentialdocuments VALUES (2, 'Финансовый отчет за 2023 год', 4, '2024-01-20', 'Выручка компании за 2023 год составила 5,3 млн руб. Основные расходы — заработная плата и закупка запчастей.', 'Strictly', 2, '\xc30d04090302e37edfd4f304016278d2c032011513efdbcd700045706d8cf4093758e450d01826122f5f74b61e5e31376a6fba7f3062939dfc08ad6ea76b742f784bb0e643f27986ed6a3e60b7f533c3165658fd0db8b71092c74ff3baa2763319aca46446e9b9d14b9493fdcb916835596e0b0bc27d601fc48a282de1c092d7e9fde09a0b57086827350e66d09c2126b1047cec6e77d6cb7280f4a6e574ca1ef4dbd00843313917d41aa4ed87550be44aec1aed718debd5467d95be1a089051c271fbc7a537b04cbb89637ba15730466675a2f55995ae238bc7830aca6ea2dc06365be31191ba0f853417b2f13972541cbcfa380103d4cd6d8ed4e3acfad8de04eec4f4');
INSERT INTO public.confidentialdocuments VALUES (3, 'Регламент технического обслуживания', 1, '2023-11-05', 'Периодичность ТО автомобилей — каждые 10 000 км. Обновлён список сертифицированных масел и фильтров.', 'Internal', 3, '\xc30d04090302a483f9cc8492168373d2c026018903b6b9411aa51f6c30b0174d6afca2c269f7cfe73c872f18432f89b13df4f679fa28d6e464d97ec515980119b03ac351deeade664bff035ba1d09cbc2ff49d858cd2f157cfb911df0edc29735dc23a3e76db663774b7c118d066b30b2f1ede7a367f2eb142a1eb1a09262ebca73d978c8a7aad5a59e00b1fd6d05705f3f21df0bd2d0decd1ce7b8aef1fcdb3327c9ea1b3c0b244e6127414051f798f4d9f88c86c830df2a7d1c903b9afb3a89d119e6cc1be7e7a8f6b05115292411445a65c2e6153e0df4a675457a4a37e8e8dc8d369df8ab59ca1c56cfcc8b01f739bf59f03fce3438c');
INSERT INTO public.confidentialdocuments VALUES (4, 'Публичная акция "Зимняя резина"', 2, '2023-10-01', 'Скидка 15% на комплект зимних шин и монтаж в период с 1 по 30 ноября 2023 года.', 'Public', 4, '\xc30d04090302e7e77c0c983d7b6270d2b401108f36715b1adb598f771b5885dcd5ebebedca84abe75fe4cd9946906f06bbcb5a013e5f2753066a2dc8d72c84399c7d209f6f2c7589f598fdcd040f3de12779158c80e528f6283d1603acdc9dad440c9500f7b8d88ac8c1997a1d34fa80b80b9eed3dcc222e527bccac71f13e06f436f4d3055ed605fce1e9552b946ba45ed3e39e9f2b7f03a717fb173133ca0b847449f5cb423ed4c463366f23b613c4c47ada0403a2f25f365d38024521eec6cd26207cbe');
INSERT INTO public.confidentialdocuments VALUES (5, 'Штатное расписание и зарплаты сотрудников', 4, '2023-12-15', 'Смирнов А.Н. — 85 000 руб., Волкова Е.А. — 65 000 руб., Данилов М.С. — 80 000 руб.', 'Strictly', 2, '\xc30d04090302b092122646f7d82a71d2ad01e27beb7d6afcbd06711d92d132c76accf6367ff6c28ed5416be81f1a5e3acb62c127eeeb1901d7a72842574be3f68693963f8995566ccba6d4ef17bed62d950c97cc1120f6a6d0777c3f13b4428224c5251bdbf016b79b5b51f02ff59fc1a4d29f2e2dd750a28606da49bb5493d96135d66152ab2f94135f81e52125302a53630841208fd3e366e8fe453cf0b3104aa1f822ab92dc9016e07ebd9926b2fe5e143c3cc6cf71a845cdb77e11a3');
INSERT INTO public.confidentialdocuments VALUES (6, 'Анализ рынка автоуслуг Москвы', 3, '2023-09-10', 'Рост спроса на услуги диагностики — 12% за последние полгода. Средний чек увеличился на 8%.', 'Confidential', 3, '\xc30d0409030242feccddc20295e177d2c0130118da109e0dd34b96320687e1a325fecebc25ef6fd6b6561ea996e165a95e657b69546d6b679f439ad7c11689a8bac21dfe164d47185ec355f2e74028de49d4beed529cdf25db26e60782396a9141903f4385724ec4ea9ced1d263cc819fbfbc0dc9f4bb192d9a1f515e1a5eca737e1de1f60bd4e30a29974f2e2e238346c3aa6314d5fb258e5ad4d2d63bc0e0e6a0dde1e4bd676e6129af130d4d3c8b9161944613656cec347b21506e32b3a5b491d49da6d80d65453d5e6310cf4aacbe234aa744587d26b057708cae2ad561cd7f20b35d9');
INSERT INTO public.confidentialdocuments VALUES (7, 'Отчет за 2025 год', 6, '2025-11-01', 'доходы расходы +500 миллионов рублей', 'Strictly', 1, '\xc30d0409030263bcbfaae80799b27ad2710187ee147c95334a80bdc99cbc1c04b522c396a122e568454adecf2eb5cda9ded24457cc01d2be7cfe465cddf53121b4ece277ad8ec5d27228aace3a177c69e4ed8e49fb1544266da7d5d327f22ea7da5143fef719fdbe6b2de64c42cb54272910140d6d8675ed2a7a654695629fcc846c');
INSERT INTO public.confidentialdocuments VALUES (13, 'Тест триггера от Смирнова', 1, '2025-11-20', 'Содержание теста', 'Public', 3, '\xc30d04090302bbe0994d35ff62d37cd250016cdc3974f6f72ae4c3054c1a64a9bd6c13bdc9fb31323a9c2d2df4b12892f30dddd79bc722e0e6bf0675086b018a567d76e465fa659865d8a13323c709fc5268242e5f94a530891b64d215f9b8939a');
INSERT INTO public.confidentialdocuments VALUES (14, 'Тест от Смирнова', 1, '2025-11-20', 'Содержание теста', 'Public', 3, '\xc30d040903025432b3633fbcb15c6fd250016c61c549214daf3356fbb8dcb7d9b1683ddf61ab9a7ece649554567cd33da166863dc13b6cc3ab6b409e541c9bc70cc42cdfa7f2a70528c2b884b9ae5267d35727165e9b0980ceaebfdb3ea38ef330');
INSERT INTO public.confidentialdocuments VALUES (15, 'Тест от Смирнова', 1, '2025-11-20', 'Содержание теста', 'Public', 3, '\xc30d040903027ab1ce68026b409474d25001e65c691b25ec631ff1c5c40d966d2ebda6017c39db12d9fcbc7bdddb381bc8f5dd0349749640f073e44b6f951985d2cf7af70266ad622ed34a994e4cfc6c591870916e3eb1f8a30e973dbd9686d486');
INSERT INTO public.confidentialdocuments VALUES (16, 'Тест от Смирнова', 1, '2025-11-20', 'Содержание теста', 'Public', 3, '\xc30d04090302a6e8754653d157466dd250013b26445a816c807323b4571c8eba0b9ec6227236243e58ef317a03704f7437d01df1553bd8cfecd40ece8a9666d138f41d0c290242372711e8a5b4194c78a9296a57b92365412c71a850c351a5144d');
INSERT INTO public.confidentialdocuments VALUES (17, 'ТЕСТ1', 5, '2025-11-20', 'аыфа', 'Internal', 5, '\xc30d04090302454cfd8fe4ca9c5362d23901d8e7908401bb25e09d077be400737d46f7949c4a6c14a9141cffdc040f7ee99a2add4e247003db1f4836052f331f72ec13cba6f4a46a3f56');
INSERT INTO public.confidentialdocuments VALUES (20, 'ТЕСТмеханика', 1, '2025-11-22', 'аыфаыфа', 'Internal', 3, NULL);
INSERT INTO public.confidentialdocuments VALUES (21, 'Менеджерский документ', 2, '2025-11-22', 'тут менеджер такой бамс', 'Internal', 4, NULL);


--
-- Data for Name: departments; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.departments VALUES (3, 'Сервисный отдел', 'Техническое обслуживание автомобилей', 1);
INSERT INTO public.departments VALUES (4, 'Отдел продаж', 'Работа с клиентами и продвижение услуг', 2);
INSERT INTO public.departments VALUES (2, 'Бухгалтерия', 'Финансовый учет и отчетность', 4);
INSERT INTO public.departments VALUES (5, 'IT-отдел', 'Обслуживание информационных систем', 5);
INSERT INTO public.departments VALUES (1, 'Администрация', 'Общее руководство компанией', 1);


--
-- Data for Name: employee_roles; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.employee_roles VALUES (1, 1, 3, '2025-11-12 16:01:43.733609', 6, true);
INSERT INTO public.employee_roles VALUES (2, 2, 2, '2025-11-12 16:01:43.733609', 6, true);
INSERT INTO public.employee_roles VALUES (3, 3, 4, '2025-11-12 16:01:43.733609', 6, true);
INSERT INTO public.employee_roles VALUES (4, 5, 5, '2025-11-12 16:01:43.733609', 6, true);
INSERT INTO public.employee_roles VALUES (5, 6, 1, '2025-11-12 16:01:43.733609', 6, true);
INSERT INTO public.employee_roles VALUES (6, 10, 2, '2025-11-19 21:59:57.289953', 5, true);


--
-- Data for Name: employeeaccess; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.employeeaccess VALUES (10, 10, 'test_user', '2025-11-13', true, '37d8d5b508cc768b991aa1a163912e8e', '2025-11-13 14:23:03.747208', true, false, '\xc30d04090302db599bb3aa47e2237cd23a0160c1b4f8231c4b87e800dac9f5d77b6a0ce340ccd20341f81b5b381b0bfb4cc375c6a8723df7a3a77930d55117e41c17f8c7847a5d3e96654e');
INSERT INTO public.employeeaccess VALUES (5, 5, 'm_danilov', '2023-05-12', true, '7f1d4afe6170aac5651f6f399bbcb81c', '2025-11-20 12:48:36.452589', true, false, '\xc30d04090302c91bea6d2ce304f47bd23a01592975c30932dc64e51543f5417bbaf70440382499dc1386b808f98990ff1f9a482a81ad413e02392af74a697635274a6a19f4d2b705eebaca');
INSERT INTO public.employeeaccess VALUES (6, 6, 'z_starkov', '2025-12-11', true, '7f1d4afe6170aac5651f6f399bbcb81c', '2025-11-20 12:50:47.673217', true, false, '\xc30d04090302131f147f65741f4766d23a011121e969183215919d3ba147d8cb626fac883fdfcea649cfc994b6a1e8d0dede3f34ae141e21978bda2226e66b94a05e8afc65190041ebeb48');
INSERT INTO public.employeeaccess VALUES (1, 1, 'a_smirnov', '2023-01-15', true, NULL, '2025-11-10 22:27:33.933649', true, false, '\xc30d04090302dd26fa1320bd5d6d64d23a01b6eaedbd74c1673aa99b8b7c584581600dbd893a89f0bb78511cad11fbec99a3154e6b331c5520c848b2b2ab2b8e8b6f7a2a4ddcb809b18e56');
INSERT INTO public.employeeaccess VALUES (3, 3, 'i_fedorov', '2023-03-10', true, NULL, '2025-11-10 22:27:33.933649', true, false, '\xc30d040903024834390c5e2b88b561d23a01adf4ae1eedd46659f6360bf3e5e5a2a7776d803203489e0b13615571c172371e4425fe3ea63acd5899361eb6020d4f5d030618be6aa56fbd40');
INSERT INTO public.employeeaccess VALUES (4, 4, 't_grigoreva', '2023-04-05', true, NULL, '2025-11-10 22:27:33.933649', true, false, '\xc30d04090302bec98c8875b6106a6bd23c014be310deb52a682ac65c3dceed04c39acbebc0ef76e6cf98a471b116d284971e88b5bd973e9638ad8c1a6f00fc28cc1ebe9cc0981270fcac2a594b');
INSERT INTO public.employeeaccess VALUES (2, 2, 'e_volkova', '2023-02-20', true, NULL, '2025-11-10 22:27:33.933649', true, false, '\xc30d0409030243fa3f04a1e68b956ad23b01a91489a6c2e336166363643f75ad91930a15640549f4660bd936c11713eef3d838d13f812b48223ce6a102f7e560802ec935e51e0ef93a23b275');
INSERT INTO public.employeeaccess VALUES (11, 11, 'test_2', '2025-11-25', true, '202cb962ac59075b964b07152d234b70', '2025-11-25 15:40:06.336926', false, true, NULL);


--
-- Data for Name: employees; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.employees VALUES (1, 'Алексей Смирнов', 'Главный механик', '+79990001111', 'smirnov@autoservice.ru', 3, '2020-03-15', 85000.00, '\xc30d04090302c6819a12250f29ad61d23d018030c6dde4d61f4ffd700dde19352c2b9914ee714755399e7668f761d1d25165b5ee09e8efc7811fc1714d6d65f8d3d7aee0acc67047166eaf03eea7', '\xc30d04090302704a40ed38f30c1361d24701dc8434922aaeb4e5bcf9f8718cc6cef689d96c1e90e8907aab04ea04c2d86349f5485fd7a547be0a6f332139e0d9dbbe2f6531d85e26245c41e278b135c50bc9635920c33b3e');
INSERT INTO public.employees VALUES (2, 'Елена Волкова', 'Менеджер по продажам', '+79990002222', 'volkova@autoservice.ru', 4, '2021-06-01', 65000.00, '\xc30d0409030266f60ade42188cd36dd23d01796c1874f7553229994b43b1d884cf1f990e3320346a2dc69c93fbb1280c3a64eee6dbea4fd91656a3ed74b510feb996735d94ce1b612020110bdb09', '\xc30d04090302b79ed21b98d96dbc72d24701efb2fe8c960ea88d2080bc229717889a292073849d0dadebef1436385c8c03187570f390b9d63e9be5f4c461b6bc77c38f05c338fc1e23455a1c693cae37b89c480031ce30c2');
INSERT INTO public.employees VALUES (3, 'Игорь Федоров', 'Диагност', '+79990003333', 'fedorov@autoservice.ru', 3, '2022-02-20', 70000.00, '\xc30d04090302c9d2e6c819c7f08972d23d0196e699b39b40d1997d4be753a3a507b3d8a472c79499d98ce781f2cdc01a401a0495721a131b6f5ca6e39591e8115c3d6331a362dc75d744741f4dee', '\xc30d040903020820fec9f95af9b579d247018ac9c6c4edcc077b8cf3394f502ec4676a0ac11e38905a0d4ffbc9ceeb128441b9d62d4865b4bee4572d55385b55636e305cfe63edd4c99a3e51f287c0cbaf42cf2b20049c7c');
INSERT INTO public.employees VALUES (4, 'Татьяна Григорьева', 'Бухгалтер', '+79990004444', 'grigoreva@autoservice.ru', 2, '2019-09-10', 90000.00, '\xc30d04090302ec37e0aa1145e67576d23d0129550969ddd5a8f151cf17e50c61bd8a34e666c82bebe4f7c26f534d518da65dbb535ea1d3c8a0a24ebb073385cf3a5cc0f443175aa07fc8bd35146e', '\xc30d040903022de25485c4d8c49b60d249013b3deb7e35e146e1fab1b87be0b7105d47b696b2ad26c5e80af899dedd8b80b7c2e9573f39cb17480ce63d73d7c348027989f9f7b2afc958747e7e901ca79e8c02a6ffecae7a05bf');
INSERT INTO public.employees VALUES (5, 'Михаил Данилов', 'Специалист по безопасности
', '+79990005555', 'danilov@autoservice.ru', 5, '2021-01-05', 80000.00, '\xc30d0409030229ffa9f90cd5770d73d23d01951571be80a17eec03d2e1fd437dfc2341a97c2de753fb2887f8b2fb927586a9f399ed6759fb2d81bc10c55b3181b1a173cf94131772816170ea0760', '\xc30d0409030269a3247d25d6a4b172d24701e0b290001cf1fd1757d5e2b61c6347fcdb1f2f1c2d3c1e80a453ccf1f7f44d84a81ca05cc521282f08d90b83fb67a7c637adcd7a0b341edfb309296f577e10c6d9b7c02fb486');
INSERT INTO public.employees VALUES (6, 'Жорик Старков', 'Главный админ', '+79997234272', 'starkov@autoservice.ru', 1, '2020-01-01', 150000.00, '\xc30d040903021e1f82f8a1e4dbe874d23d0134c94bfce686478781b45d4a4945f9f2827d6dbd2fabb601d79c9685ae601147f0a2ecf141dfed4c5bf784d10a85a34878f510a69ca165b6293cd0ce', '\xc30d04090302c64407f969a91f4b7cd247016a1edcfc62de69f1e22b618ed9e1c693a28375756d7f2cf93e0afdf83b1d7c73a467e926e7bcb388d0fda85a7f9a65fcdb444ec4ab4e8d58d63003c18f950c8ecf786cc5e579');
INSERT INTO public.employees VALUES (9, 'Вовачик Кривой', 'механик', '+72218767712', 'ssg@gmail.com', 3, '2025-11-12', 30000.00, '\xc30d040903022e6b47f9f417a5546bd23d01e6883e6c44ce43b5235132846a578ec9704dbe5f8734d83e5e3474e9545e48612e3aca35f0e9b21c68be2988e6798149b07f193de46c80bcfe079202', '\xc30d040903028a977f8251ba8d686ad23e01b8bb0d99800140df87aae7bdf8932d955f7ea6bd8f667071ea05a77c24af7e023ae825d57b8b5dc84396f340434922cd05c74d10a4ff355151f5f291ad');
INSERT INTO public.employees VALUES (10, 'Тестовый Пользователь', 'Тестировщик', '+79990009999', 'test@autoservice.ru', 3, '2025-11-13', 50000.00, '\xc30d040903023090f554e57435486dd23d01aa5276ba321c8437c953e6f431245a2e8da44a3f07b1fa9d6414ddfd6201baca4698b6002146b935268386f9f60b6111ad6da443729e76e573b1000f', '\xc30d04090302eb66f783a82ba0a278d2440130b78c9bd5f22f769203432608435f2c463f1d8356c939691c4de82ce22de115c68aa372e36e081f1a8e13a2fbde9f50556380ed76b8458afdb3b83ec2ea1e5b503cf9');
INSERT INTO public.employees VALUES (11, 'Тест2', 'менеджер3', '+7-900-000-00-65', 'ivanov@mail.ru', 4, '2025-11-25', 37000.00, NULL, NULL);


--
-- Data for Name: encrypted_data_access_log; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: encryption_keys; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.encryption_keys VALUES (1, 'email_key', 'email_encryption_key_2024', 1, 'email', '2025-11-20 14:32:34.173635', 'postgres', true);
INSERT INTO public.encryption_keys VALUES (2, 'phone_key', 'phone_encryption_key_2024', 1, 'phone', '2025-11-20 14:32:34.173635', 'postgres', true);
INSERT INTO public.encryption_keys VALUES (3, 'address_key', 'address_encryption_key_2024', 1, 'address', '2025-11-20 14:32:34.173635', 'postgres', true);
INSERT INTO public.encryption_keys VALUES (4, 'document_key', 'document_encryption_key_2024', 1, 'document', '2025-11-20 14:32:34.173635', 'postgres', true);
INSERT INTO public.encryption_keys VALUES (5, 'login_key', 'login_encryption_key_2024', 1, 'login', '2025-11-20 14:32:34.173635', 'postgres', true);


--
-- Data for Name: makes; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.makes VALUES (1, 'Toyota');
INSERT INTO public.makes VALUES (2, 'BMW');
INSERT INTO public.makes VALUES (3, 'Hyundai');
INSERT INTO public.makes VALUES (4, 'Volkswagen');
INSERT INTO public.makes VALUES (5, 'Ford');
INSERT INTO public.makes VALUES (6, 'Havall');


--
-- Data for Name: models; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.models VALUES (1, 1, 'Camry');
INSERT INTO public.models VALUES (2, 1, 'Corolla');
INSERT INTO public.models VALUES (4, 3, 'Tucson');
INSERT INTO public.models VALUES (5, 4, 'Passat');
INSERT INTO public.models VALUES (6, 5, 'Focus');
INSERT INTO public.models VALUES (3, 2, 'X6');


--
-- Data for Name: orders; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.orders VALUES (2, 2, 3, '2024-04-02', 'Выполнен', NULL);
INSERT INTO public.orders VALUES (4, 4, 2, '2024-06-20', 'Выполнен', NULL);
INSERT INTO public.orders VALUES (1, 1, 1, '2024-03-10', 'Выполнен', 4500.00);
INSERT INTO public.orders VALUES (6, 2, 1, '2025-02-02', 'В процессе ', 4500.00);
INSERT INTO public.orders VALUES (5, 5, 3, '2024-07-01', 'Выполнен', NULL);
INSERT INTO public.orders VALUES (3, 3, 1, '2024-05-12', 'Ожидает запчасти', NULL);


--
-- Data for Name: orderservices; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.orderservices VALUES (1, 1, 1);
INSERT INTO public.orderservices VALUES (2, 2, 2);
INSERT INTO public.orderservices VALUES (3, 3, 3);
INSERT INTO public.orderservices VALUES (4, 4, 4);
INSERT INTO public.orderservices VALUES (5, 5, 5);
INSERT INTO public.orderservices VALUES (6, 1, 4);
INSERT INTO public.orderservices VALUES (7, 6, 3);


--
-- Data for Name: password_history; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.password_history VALUES (1, 10, '51d52185881c0ba65d1d4efc605c320d', '2025-11-13 14:12:55.046636', 10);
INSERT INTO public.password_history VALUES (2, 10, '37d8d5b508cc768b991aa1a163912e8e', '2025-11-13 14:23:03.747208', 10);
INSERT INTO public.password_history VALUES (3, 5, '7f1d4afe6170aac5651f6f399bbcb81c', '2025-11-20 12:48:36.452589', 5);
INSERT INTO public.password_history VALUES (4, 6, '7f1d4afe6170aac5651f6f399bbcb81c', '2025-11-20 12:50:47.673217', 6);
INSERT INTO public.password_history VALUES (5, 11, '202cb962ac59075b964b07152d234b70', '2025-11-25 15:40:06.336926', 11);


--
-- Data for Name: permissions; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.permissions VALUES (1, 'view_clients', 'Просмотр клиентов через представление', 'VIEW', 'v_clients', 'SELECT');
INSERT INTO public.permissions VALUES (2, 'view_cars', 'Просмотр автомобилей через представление', 'VIEW', 'v_cars', 'SELECT');
INSERT INTO public.permissions VALUES (3, 'view_orders', 'Просмотр заказов через представление', 'VIEW', 'v_orders', 'SELECT');
INSERT INTO public.permissions VALUES (4, 'view_order_services', 'Просмотр услуг в заказах через представление', 'VIEW', 'v_order_services', 'SELECT');
INSERT INTO public.permissions VALUES (5, 'view_services', 'Просмотр услуг через представление', 'VIEW', 'v_services', 'SELECT');
INSERT INTO public.permissions VALUES (6, 'view_service_categories', 'Просмотр категорий услуг', 'VIEW', 'v_service_categories', 'SELECT');
INSERT INTO public.permissions VALUES (7, 'view_departments', 'Просмотр отделов', 'VIEW', 'v_departments', 'SELECT');
INSERT INTO public.permissions VALUES (8, 'insert_clients', 'Добавление клиентов', 'TABLE', 'clients', 'INSERT');
INSERT INTO public.permissions VALUES (9, 'update_clients', 'Изменение клиентов', 'TABLE', 'clients', 'UPDATE');
INSERT INTO public.permissions VALUES (10, 'delete_clients', 'Удаление клиентов', 'TABLE', 'clients', 'DELETE');
INSERT INTO public.permissions VALUES (11, 'insert_cars', 'Добавление автомобилей', 'TABLE', 'cars', 'INSERT');
INSERT INTO public.permissions VALUES (12, 'update_cars', 'Изменение автомобилей', 'TABLE', 'cars', 'UPDATE');
INSERT INTO public.permissions VALUES (13, 'delete_cars', 'Удаление автомобилей', 'TABLE', 'cars', 'DELETE');
INSERT INTO public.permissions VALUES (14, 'insert_orders', 'Создание заказов', 'TABLE', 'orders', 'INSERT');
INSERT INTO public.permissions VALUES (15, 'update_orders', 'Изменение заказов', 'TABLE', 'orders', 'UPDATE');
INSERT INTO public.permissions VALUES (16, 'delete_orders', 'Удаление заказов', 'TABLE', 'orders', 'DELETE');
INSERT INTO public.permissions VALUES (17, 'insert_order_services', 'Добавление услуг в заказы', 'TABLE', 'orderservices', 'INSERT');
INSERT INTO public.permissions VALUES (18, 'update_order_services', 'Изменение услуг в заказах', 'TABLE', 'orderservices', 'UPDATE');
INSERT INTO public.permissions VALUES (19, 'delete_order_services', 'Удаление услуг в заказах', 'TABLE', 'orderservices', 'DELETE');
INSERT INTO public.permissions VALUES (20, 'view_orders_senior', 'Просмотр заказов', 'VIEW', 'v_orders', 'SELECT');
INSERT INTO public.permissions VALUES (21, 'view_order_services_senior', 'Просмотр услуг в заказах', 'VIEW', 'v_order_services', 'SELECT');
INSERT INTO public.permissions VALUES (22, 'view_services_senior', 'Просмотр услуг', 'VIEW', 'v_services', 'SELECT');
INSERT INTO public.permissions VALUES (23, 'view_cars_senior', 'Просмотр автомобилей', 'VIEW', 'v_cars', 'SELECT');
INSERT INTO public.permissions VALUES (24, 'view_clients_senior', 'Просмотр клиентов', 'VIEW', 'v_clients', 'SELECT');
INSERT INTO public.permissions VALUES (25, 'update_order_status', 'Изменение статуса заказа', 'TABLE', 'orders', 'UPDATE');
INSERT INTO public.permissions VALUES (26, 'view_orders_junior', 'Просмотр заказов', 'VIEW', 'v_orders', 'SELECT');
INSERT INTO public.permissions VALUES (27, 'view_order_services_junior', 'Просмотр услуг в заказах', 'VIEW', 'v_order_services', 'SELECT');
INSERT INTO public.permissions VALUES (28, 'view_services_junior', 'Просмотр услуг', 'VIEW', 'v_services', 'SELECT');
INSERT INTO public.permissions VALUES (29, 'view_cars_junior', 'Просмотр автомобилей', 'VIEW', 'v_cars', 'SELECT');
INSERT INTO public.permissions VALUES (30, 'view_clients_junior', 'Просмотр клиентов', 'VIEW', 'v_clients', 'SELECT');
INSERT INTO public.permissions VALUES (31, 'view_conf_docs', 'Просмотр конфиденциальных документов', 'VIEW', 'v_confidential_documents', 'SELECT');
INSERT INTO public.permissions VALUES (32, 'view_employee_access', 'Просмотр пропусков сотрудников', 'VIEW', 'v_employee_access', 'SELECT');
INSERT INTO public.permissions VALUES (33, 'view_employees', 'Просмотр сотрудников', 'VIEW', 'v_employees', 'SELECT');
INSERT INTO public.permissions VALUES (34, 'view_password_history', 'Просмотр истории паролей', 'TABLE', 'password_history', 'SELECT');
INSERT INTO public.permissions VALUES (35, 'view_employeeaccess', 'Просмотр таблицы пропусков', 'TABLE', 'employeeaccess', 'SELECT');
INSERT INTO public.permissions VALUES (36, 'view_roles', 'Просмотр ролей', 'TABLE', 'roles', 'SELECT');
INSERT INTO public.permissions VALUES (37, 'view_role_permissions', 'Просмотр привилегий ролей', 'TABLE', 'role_permissions', 'SELECT');
INSERT INTO public.permissions VALUES (38, 'view_employee_roles', 'Просмотр ролей сотрудников', 'TABLE', 'employee_roles', 'SELECT');
INSERT INTO public.permissions VALUES (39, 'view_audit_log', 'Просмотр аудита', 'TABLE', 'audit_log', 'SELECT');
INSERT INTO public.permissions VALUES (40, 'view_confidential_documents', 'Просмотр таблицы конфиденциальных документов', 'TABLE', 'confidentialdocuments', 'SELECT');
INSERT INTO public.permissions VALUES (41, 'superadmin_all_tables', 'Полный доступ ко всем таблицам', 'SCHEMA', 'public', 'ALL');
INSERT INTO public.permissions VALUES (42, 'superadmin_all_sequences', 'Полный доступ к последовательностям', 'SCHEMA', 'public', 'ALL');
INSERT INTO public.permissions VALUES (43, 'superadmin_schema', 'Полный контроль над схемой public', 'SCHEMA', 'public', 'ALL');


--
-- Data for Name: role_permissions; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.role_permissions VALUES (1, 2, 1, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (2, 2, 2, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (3, 2, 3, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (4, 2, 4, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (5, 2, 5, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (6, 2, 6, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (7, 2, 7, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (8, 2, 8, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (9, 2, 9, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (10, 2, 10, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (11, 2, 11, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (12, 2, 12, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (13, 2, 13, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (14, 2, 14, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (15, 2, 15, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (16, 2, 16, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (17, 2, 17, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (18, 2, 18, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (19, 2, 19, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (20, 2, 20, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (21, 2, 21, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (22, 2, 22, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (23, 2, 23, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (24, 2, 24, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (25, 2, 25, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (26, 2, 26, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (27, 2, 27, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (28, 2, 28, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (29, 2, 29, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (30, 2, 30, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (31, 2, 31, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (32, 2, 32, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (33, 2, 33, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (34, 2, 34, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (35, 2, 35, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (36, 2, 36, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (37, 2, 37, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (38, 2, 38, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (39, 2, 39, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (40, 2, 40, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (41, 3, 20, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (42, 3, 21, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (43, 3, 22, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (44, 3, 23, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (45, 3, 24, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (46, 3, 25, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (47, 4, 26, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (48, 4, 27, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (49, 4, 28, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (50, 4, 29, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (51, 4, 30, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (52, 5, 31, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (53, 5, 32, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (54, 5, 33, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (55, 5, 35, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (56, 5, 36, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (57, 5, 38, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (58, 5, 39, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (59, 5, 40, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (60, 1, 41, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (61, 1, 42, '2025-11-12 15:53:31.952112', NULL);
INSERT INTO public.role_permissions VALUES (62, 1, 43, '2025-11-12 15:53:31.952112', NULL);


--
-- Data for Name: roles; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.roles VALUES (1, 'superadmin', 'Полный доступ к системе, управляет всеми данными и пользователями', '2025-11-10 22:54:49.438922');
INSERT INTO public.roles VALUES (2, 'manager', 'Менеджер, управляет заказами и клиентами', '2025-11-10 22:54:49.438922');
INSERT INTO public.roles VALUES (3, 'senior_mechanic', 'Старший механик, управляет техническими работами и заказами', '2025-11-10 22:54:49.438922');
INSERT INTO public.roles VALUES (4, 'junior_employee', 'Обычный сотрудник, выполняет заказы и услуги', '2025-11-10 22:54:49.438922');
INSERT INTO public.roles VALUES (5, 'security_officer', 'Офицер безопасности, контролирует логи, пароли и документы', '2025-11-10 22:54:49.438922');


--
-- Data for Name: servicecategories; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.servicecategories VALUES (1, 'ТО', 'Техническое обслуживание автомобилей');
INSERT INTO public.servicecategories VALUES (2, 'Диагностика', 'Компьютерные и визуальные проверки состояния');
INSERT INTO public.servicecategories VALUES (3, 'Ремонт', 'Замена и восстановление деталей');
INSERT INTO public.servicecategories VALUES (4, 'Шиномонтаж', 'Работы с колесами и шинами');
INSERT INTO public.servicecategories VALUES (5, 'Уход', 'Мойка, полировка, уход за кузовом и салоном');
INSERT INTO public.servicecategories VALUES (6, 'Кузовной ремонт', 'Здесь мы чиним ваши кузовы, отрежем старый приварим новый');
INSERT INTO public.servicecategories VALUES (7, 'Электрика', 'Настройка электрики');


--
-- Data for Name: services; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.services VALUES (1, 'Замена масла', 'Полная замена моторного масла и фильтра', 2500.00, 60, 1);
INSERT INTO public.services VALUES (2, 'Диагностика двигателя', 'Компьютерная проверка состояния ДВС', 3000.00, 90, 2);
INSERT INTO public.services VALUES (3, 'Ремонт тормозной системы', 'Замена колодок и дисков', 4500.00, 120, 3);
INSERT INTO public.services VALUES (4, 'Замена шин', 'Сезонная смена комплекта шин', 2000.00, 45, 4);
INSERT INTO public.services VALUES (5, 'Мойка кузова', 'Наружная и внутренняя чистка автомобиля', 1500.00, 30, 5);
INSERT INTO public.services VALUES (7, 'Замена колодок ', 'меняем колодки передние и задние', 2000.00, 40, 5);


--
-- Name: audit_log_audit_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.audit_log_audit_id_seq', 49, true);


--
-- Name: cars_carid_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.cars_carid_seq', 8, true);


--
-- Name: clients_clientid_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.clients_clientid_seq', 10, true);


--
-- Name: confidentialdocuments_docid_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.confidentialdocuments_docid_seq', 21, true);


--
-- Name: departments_department_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.departments_department_id_seq', 5, true);


--
-- Name: employee_roles_employee_role_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.employee_roles_employee_role_id_seq', 6, true);


--
-- Name: employeeaccess_accessid_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.employeeaccess_accessid_seq', 11, true);


--
-- Name: employees_employeeid_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.employees_employeeid_seq', 11, true);


--
-- Name: encrypted_data_access_log_access_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.encrypted_data_access_log_access_id_seq', 1, false);


--
-- Name: encryption_keys_key_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.encryption_keys_key_id_seq', 5, true);


--
-- Name: makes_makeid_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.makes_makeid_seq', 6, true);


--
-- Name: models_modelid_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.models_modelid_seq', 6, true);


--
-- Name: orders_orderid_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.orders_orderid_seq', 6, true);


--
-- Name: orderservices_orderserviceid_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.orderservices_orderserviceid_seq', 7, true);


--
-- Name: password_history_history_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.password_history_history_id_seq', 5, true);


--
-- Name: permissions_permission_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.permissions_permission_id_seq', 44, true);


--
-- Name: role_permissions_role_permission_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.role_permissions_role_permission_id_seq', 62, true);


--
-- Name: roles_role_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.roles_role_id_seq', 5, true);


--
-- Name: servicecategories_categoryid_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.servicecategories_categoryid_seq', 7, true);


--
-- Name: services_serviceid_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.services_serviceid_seq', 7, true);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (audit_id);


--
-- Name: cars cars_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cars
    ADD CONSTRAINT cars_pkey PRIMARY KEY (carid);


--
-- Name: cars cars_vin_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cars
    ADD CONSTRAINT cars_vin_key UNIQUE (vin);


--
-- Name: clients clients_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.clients
    ADD CONSTRAINT clients_pkey PRIMARY KEY (clientid);


--
-- Name: confidentialdocuments confidentialdocuments_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.confidentialdocuments
    ADD CONSTRAINT confidentialdocuments_pkey PRIMARY KEY (docid);


--
-- Name: departments departments_department_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_department_name_key UNIQUE (department_name);


--
-- Name: departments departments_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_pkey PRIMARY KEY (department_id);


--
-- Name: employee_roles employee_roles_employee_id_role_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employee_roles
    ADD CONSTRAINT employee_roles_employee_id_role_id_key UNIQUE (employee_id, role_id);


--
-- Name: employee_roles employee_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employee_roles
    ADD CONSTRAINT employee_roles_pkey PRIMARY KEY (employee_role_id);


--
-- Name: employeeaccess employeeaccess_employeeid_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employeeaccess
    ADD CONSTRAINT employeeaccess_employeeid_key UNIQUE (employeeid);


--
-- Name: employeeaccess employeeaccess_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employeeaccess
    ADD CONSTRAINT employeeaccess_pkey PRIMARY KEY (accessid);


--
-- Name: employeeaccess employeeaccess_systemlogin_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employeeaccess
    ADD CONSTRAINT employeeaccess_systemlogin_key UNIQUE (systemlogin);


--
-- Name: employees employees_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employees
    ADD CONSTRAINT employees_pkey PRIMARY KEY (employeeid);


--
-- Name: encrypted_data_access_log encrypted_data_access_log_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.encrypted_data_access_log
    ADD CONSTRAINT encrypted_data_access_log_pkey PRIMARY KEY (access_id);


--
-- Name: encryption_keys encryption_keys_key_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.encryption_keys
    ADD CONSTRAINT encryption_keys_key_name_key UNIQUE (key_name);


--
-- Name: encryption_keys encryption_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.encryption_keys
    ADD CONSTRAINT encryption_keys_pkey PRIMARY KEY (key_id);


--
-- Name: makes makes_makename_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.makes
    ADD CONSTRAINT makes_makename_key UNIQUE (makename);


--
-- Name: makes makes_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.makes
    ADD CONSTRAINT makes_pkey PRIMARY KEY (makeid);


--
-- Name: models models_makeid_modelname_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.models
    ADD CONSTRAINT models_makeid_modelname_key UNIQUE (makeid, modelname);


--
-- Name: models models_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.models
    ADD CONSTRAINT models_pkey PRIMARY KEY (modelid);


--
-- Name: orders orders_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (orderid);


--
-- Name: orderservices orderservices_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orderservices
    ADD CONSTRAINT orderservices_pkey PRIMARY KEY (orderserviceid);


--
-- Name: password_history password_history_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.password_history
    ADD CONSTRAINT password_history_pkey PRIMARY KEY (history_id);


--
-- Name: permissions permissions_permission_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_permission_name_key UNIQUE (permission_name);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (permission_id);


--
-- Name: role_permissions role_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (role_permission_id);


--
-- Name: role_permissions role_permissions_role_id_permission_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_role_id_permission_id_key UNIQUE (role_id, permission_id);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (role_id);


--
-- Name: roles roles_role_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_role_name_key UNIQUE (role_name);


--
-- Name: servicecategories servicecategories_categoryname_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.servicecategories
    ADD CONSTRAINT servicecategories_categoryname_key UNIQUE (categoryname);


--
-- Name: servicecategories servicecategories_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.servicecategories
    ADD CONSTRAINT servicecategories_pkey PRIMARY KEY (categoryid);


--
-- Name: services services_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_pkey PRIMARY KEY (serviceid);


--
-- Name: services services_servicename_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_servicename_key UNIQUE (servicename);


--
-- Name: confidentialdocuments trg_auto_set_department; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_auto_set_department BEFORE INSERT ON public.confidentialdocuments FOR EACH ROW EXECUTE FUNCTION public.auto_set_department();


--
-- Name: orderservices trg_order_total_delete; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_order_total_delete AFTER DELETE ON public.orderservices FOR EACH ROW EXECUTE FUNCTION public.fn_update_order_total();


--
-- Name: orderservices trg_order_total_insert; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_order_total_insert AFTER INSERT ON public.orderservices FOR EACH ROW EXECUTE FUNCTION public.fn_update_order_total();


--
-- Name: orderservices trg_order_total_update; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_order_total_update AFTER UPDATE ON public.orderservices FOR EACH ROW EXECUTE FUNCTION public.fn_update_order_total();


--
-- Name: cars cars_clientid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cars
    ADD CONSTRAINT cars_clientid_fkey FOREIGN KEY (clientid) REFERENCES public.clients(clientid) ON DELETE CASCADE;


--
-- Name: cars cars_modelid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cars
    ADD CONSTRAINT cars_modelid_fkey FOREIGN KEY (modelid) REFERENCES public.models(modelid) ON DELETE CASCADE;


--
-- Name: confidentialdocuments confidentialdocuments_creatorid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.confidentialdocuments
    ADD CONSTRAINT confidentialdocuments_creatorid_fkey FOREIGN KEY (creatorid) REFERENCES public.employees(employeeid);


--
-- Name: confidentialdocuments confidentialdocuments_department_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.confidentialdocuments
    ADD CONSTRAINT confidentialdocuments_department_id_fkey FOREIGN KEY (department_id) REFERENCES public.departments(department_id);


--
-- Name: employee_roles employee_roles_assigned_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employee_roles
    ADD CONSTRAINT employee_roles_assigned_by_fkey FOREIGN KEY (assigned_by) REFERENCES public.employees(employeeid);


--
-- Name: employee_roles employee_roles_employee_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employee_roles
    ADD CONSTRAINT employee_roles_employee_id_fkey FOREIGN KEY (employee_id) REFERENCES public.employees(employeeid) ON DELETE CASCADE;


--
-- Name: employee_roles employee_roles_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employee_roles
    ADD CONSTRAINT employee_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(role_id) ON DELETE CASCADE;


--
-- Name: employeeaccess employeeaccess_employeeid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employeeaccess
    ADD CONSTRAINT employeeaccess_employeeid_fkey FOREIGN KEY (employeeid) REFERENCES public.employees(employeeid) ON DELETE CASCADE;


--
-- Name: employees employees_department_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.employees
    ADD CONSTRAINT employees_department_id_fkey FOREIGN KEY (department_id) REFERENCES public.departments(department_id);


--
-- Name: departments fk_department_manager; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT fk_department_manager FOREIGN KEY (manager_id) REFERENCES public.employees(employeeid);


--
-- Name: models models_makeid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.models
    ADD CONSTRAINT models_makeid_fkey FOREIGN KEY (makeid) REFERENCES public.makes(makeid) ON DELETE CASCADE;


--
-- Name: orders orders_carid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_carid_fkey FOREIGN KEY (carid) REFERENCES public.cars(carid);


--
-- Name: orders orders_employeeid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_employeeid_fkey FOREIGN KEY (employeeid) REFERENCES public.employees(employeeid);


--
-- Name: orderservices orderservices_orderid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orderservices
    ADD CONSTRAINT orderservices_orderid_fkey FOREIGN KEY (orderid) REFERENCES public.orders(orderid);


--
-- Name: orderservices orderservices_serviceid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orderservices
    ADD CONSTRAINT orderservices_serviceid_fkey FOREIGN KEY (serviceid) REFERENCES public.services(serviceid);


--
-- Name: password_history password_history_changed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.password_history
    ADD CONSTRAINT password_history_changed_by_fkey FOREIGN KEY (changed_by) REFERENCES public.employees(employeeid);


--
-- Name: password_history password_history_employee_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.password_history
    ADD CONSTRAINT password_history_employee_id_fkey FOREIGN KEY (employee_id) REFERENCES public.employees(employeeid) ON DELETE CASCADE;


--
-- Name: role_permissions role_permissions_granted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES public.employees(employeeid);


--
-- Name: role_permissions role_permissions_permission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.permissions(permission_id) ON DELETE CASCADE;


--
-- Name: role_permissions role_permissions_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(role_id) ON DELETE CASCADE;


--
-- Name: services services_categoryid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_categoryid_fkey FOREIGN KEY (categoryid) REFERENCES public.servicecategories(categoryid);


--
-- Name: confidentialdocuments; Type: ROW SECURITY; Schema: public; Owner: postgres
--

ALTER TABLE public.confidentialdocuments ENABLE ROW LEVEL SECURITY;

--
-- Name: confidentialdocuments department_head_policy; Type: POLICY; Schema: public; Owner: postgres
--

CREATE POLICY department_head_policy ON public.confidentialdocuments USING (((CURRENT_USER <> ALL (ARRAY['security_officer'::name, 'superadmin'::name])) AND (((accesslevel)::text = 'Public'::text) OR (public.is_department_head(department_id) AND ((accesslevel)::text <> 'Strictly'::text))))) WITH CHECK (((CURRENT_USER <> ALL (ARRAY['security_officer'::name, 'superadmin'::name])) AND (public.is_department_head(department_id) AND ((accesslevel)::text <> 'Strictly'::text))));


--
-- Name: confidentialdocuments employee_policy; Type: POLICY; Schema: public; Owner: postgres
--

CREATE POLICY employee_policy ON public.confidentialdocuments USING (((CURRENT_USER <> ALL (ARRAY['security_officer'::name, 'superadmin'::name])) AND (((accesslevel)::text = 'Public'::text) OR ((department_id = public.get_current_department_id()) AND ((accesslevel)::text <> 'Strictly'::text)) OR (creatorid = public.get_current_employee_id())))) WITH CHECK (((CURRENT_USER <> ALL (ARRAY['security_officer'::name, 'superadmin'::name])) AND ((department_id = public.get_current_department_id()) AND (creatorid = public.get_current_employee_id()))));


--
-- Name: confidentialdocuments insert_documents_policy; Type: POLICY; Schema: public; Owner: postgres
--

CREATE POLICY insert_documents_policy ON public.confidentialdocuments FOR INSERT WITH CHECK (true);


--
-- Name: confidentialdocuments security_policy; Type: POLICY; Schema: public; Owner: postgres
--

CREATE POLICY security_policy ON public.confidentialdocuments USING ((CURRENT_USER = ANY (ARRAY['security_officer'::name, 'm_danilov'::name]))) WITH CHECK ((CURRENT_USER = ANY (ARRAY['security_officer'::name, 'm_danilov'::name])));


--
-- Name: confidentialdocuments superadmin_policy; Type: POLICY; Schema: public; Owner: postgres
--

CREATE POLICY superadmin_policy ON public.confidentialdocuments USING ((CURRENT_USER = ANY (ARRAY['superadmin'::name, 'z_starkov'::name]))) WITH CHECK ((CURRENT_USER = ANY (ARRAY['superadmin'::name, 'z_starkov'::name])));


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: pg_database_owner
--

GRANT ALL ON SCHEMA public TO superadmin;
GRANT USAGE ON SCHEMA public TO manager;
GRANT USAGE ON SCHEMA public TO senior_mechanic;
GRANT USAGE ON SCHEMA public TO junior_employee;
GRANT USAGE ON SCHEMA public TO security_officer;


--
-- Name: FUNCTION change_employee_password(p_employee_id integer, p_login text, p_new_password text); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.change_employee_password(p_employee_id integer, p_login text, p_new_password text) TO manager;
GRANT ALL ON FUNCTION public.change_employee_password(p_employee_id integer, p_login text, p_new_password text) TO senior_mechanic;
GRANT ALL ON FUNCTION public.change_employee_password(p_employee_id integer, p_login text, p_new_password text) TO junior_employee;
GRANT ALL ON FUNCTION public.change_employee_password(p_employee_id integer, p_login text, p_new_password text) TO security_officer;
GRANT ALL ON FUNCTION public.change_employee_password(p_employee_id integer, p_login text, p_new_password text) TO superadmin;


--
-- Name: FUNCTION change_employee_password_secure(p_employee_id integer, p_login text, p_new_password text); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.change_employee_password_secure(p_employee_id integer, p_login text, p_new_password text) TO security_officer;
GRANT ALL ON FUNCTION public.change_employee_password_secure(p_employee_id integer, p_login text, p_new_password text) TO manager;
GRANT ALL ON FUNCTION public.change_employee_password_secure(p_employee_id integer, p_login text, p_new_password text) TO senior_mechanic;
GRANT ALL ON FUNCTION public.change_employee_password_secure(p_employee_id integer, p_login text, p_new_password text) TO junior_employee;
GRANT ALL ON FUNCTION public.change_employee_password_secure(p_employee_id integer, p_login text, p_new_password text) TO superadmin;


--
-- Name: FUNCTION check_password_history(p_employee_id integer, p_new_hash text); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.check_password_history(p_employee_id integer, p_new_hash text) TO security_officer;
GRANT ALL ON FUNCTION public.check_password_history(p_employee_id integer, p_new_hash text) TO superadmin;


--
-- Name: FUNCTION check_password_policy(p_login text, p_password text); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.check_password_policy(p_login text, p_password text) TO security_officer;
GRANT ALL ON FUNCTION public.check_password_policy(p_login text, p_password text) TO superadmin;


--
-- Name: FUNCTION fn_add_car(p_clientid integer, p_modelid integer, p_year integer, p_vin character varying, p_license character varying, p_color character varying); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_add_car(p_clientid integer, p_modelid integer, p_year integer, p_vin character varying, p_license character varying, p_color character varying) TO manager;
GRANT ALL ON FUNCTION public.fn_add_car(p_clientid integer, p_modelid integer, p_year integer, p_vin character varying, p_license character varying, p_color character varying) TO superadmin;


--
-- Name: FUNCTION fn_add_client(p_fullname character varying, p_phone character varying, p_email character varying, p_address character varying); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_add_client(p_fullname character varying, p_phone character varying, p_email character varying, p_address character varying) TO superadmin;


--
-- Name: FUNCTION fn_add_client(p_fullname text, p_phone text, p_email text, p_address text, p_registration_date date); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_add_client(p_fullname text, p_phone text, p_email text, p_address text, p_registration_date date) TO superadmin;


--
-- Name: FUNCTION fn_add_department(p_name character varying, p_desc text); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_add_department(p_name character varying, p_desc text) TO superadmin;


--
-- Name: FUNCTION fn_add_employee(p_fullname character varying, p_position character varying, p_phone character varying, p_email character varying, p_department_id integer, p_hiredate date, p_salary numeric); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_add_employee(p_fullname character varying, p_position character varying, p_phone character varying, p_email character varying, p_department_id integer, p_hiredate date, p_salary numeric) TO manager;
GRANT ALL ON FUNCTION public.fn_add_employee(p_fullname character varying, p_position character varying, p_phone character varying, p_email character varying, p_department_id integer, p_hiredate date, p_salary numeric) TO superadmin;


--
-- Name: FUNCTION fn_add_make(p_name character varying); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_add_make(p_name character varying) TO manager;
GRANT ALL ON FUNCTION public.fn_add_make(p_name character varying) TO superadmin;


--
-- Name: FUNCTION fn_add_model(p_makeid integer, p_modelname character varying); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_add_model(p_makeid integer, p_modelname character varying) TO manager;
GRANT ALL ON FUNCTION public.fn_add_model(p_makeid integer, p_modelname character varying) TO superadmin;


--
-- Name: FUNCTION fn_add_order(p_carid integer, p_employeeid integer, p_orderdate date, p_status character varying, p_totalamount numeric); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_add_order(p_carid integer, p_employeeid integer, p_orderdate date, p_status character varying, p_totalamount numeric) TO manager;
GRANT ALL ON FUNCTION public.fn_add_order(p_carid integer, p_employeeid integer, p_orderdate date, p_status character varying, p_totalamount numeric) TO superadmin;


--
-- Name: FUNCTION fn_add_order_service(p_orderid integer, p_serviceid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_add_order_service(p_orderid integer, p_serviceid integer) TO superadmin;


--
-- Name: FUNCTION fn_add_service(p_servicename character varying, p_description text, p_price numeric, p_durationminutes integer, p_categoryid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_add_service(p_servicename character varying, p_description text, p_price numeric, p_durationminutes integer, p_categoryid integer) TO manager;
GRANT ALL ON FUNCTION public.fn_add_service(p_servicename character varying, p_description text, p_price numeric, p_durationminutes integer, p_categoryid integer) TO superadmin;


--
-- Name: FUNCTION fn_add_service_category(p_name character varying, p_description text); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_add_service_category(p_name character varying, p_description text) TO manager;
GRANT ALL ON FUNCTION public.fn_add_service_category(p_name character varying, p_description text) TO superadmin;


--
-- Name: FUNCTION fn_delete_car(p_carid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_delete_car(p_carid integer) TO manager;
GRANT ALL ON FUNCTION public.fn_delete_car(p_carid integer) TO superadmin;


--
-- Name: FUNCTION fn_delete_client(p_clientid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_delete_client(p_clientid integer) TO superadmin;


--
-- Name: FUNCTION fn_delete_employee(p_employee_id integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_delete_employee(p_employee_id integer) TO manager;
GRANT ALL ON FUNCTION public.fn_delete_employee(p_employee_id integer) TO superadmin;


--
-- Name: FUNCTION fn_delete_employee_role(p_employee_role_id integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_delete_employee_role(p_employee_role_id integer) TO security_officer;
GRANT ALL ON FUNCTION public.fn_delete_employee_role(p_employee_role_id integer) TO superadmin;


--
-- Name: FUNCTION fn_delete_employeeaccess(p_accessid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_delete_employeeaccess(p_accessid integer) TO security_officer;
GRANT ALL ON FUNCTION public.fn_delete_employeeaccess(p_accessid integer) TO superadmin;


--
-- Name: FUNCTION fn_delete_make(p_id integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_delete_make(p_id integer) TO manager;
GRANT ALL ON FUNCTION public.fn_delete_make(p_id integer) TO superadmin;


--
-- Name: FUNCTION fn_delete_model(p_id integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_delete_model(p_id integer) TO manager;
GRANT ALL ON FUNCTION public.fn_delete_model(p_id integer) TO superadmin;


--
-- Name: FUNCTION fn_delete_order(p_orderid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_delete_order(p_orderid integer) TO manager;
GRANT ALL ON FUNCTION public.fn_delete_order(p_orderid integer) TO superadmin;


--
-- Name: FUNCTION fn_delete_order_service(p_orderserviceid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_delete_order_service(p_orderserviceid integer) TO superadmin;


--
-- Name: FUNCTION fn_delete_permission(p_permission_id integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_delete_permission(p_permission_id integer) TO superadmin;


--
-- Name: FUNCTION fn_delete_service(p_serviceid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_delete_service(p_serviceid integer) TO manager;
GRANT ALL ON FUNCTION public.fn_delete_service(p_serviceid integer) TO superadmin;


--
-- Name: FUNCTION fn_delete_service_category(p_id integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_delete_service_category(p_id integer) TO manager;
GRANT ALL ON FUNCTION public.fn_delete_service_category(p_id integer) TO superadmin;


--
-- Name: FUNCTION fn_get_all_cars(); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_all_cars() TO manager;
GRANT ALL ON FUNCTION public.fn_get_all_cars() TO superadmin;


--
-- Name: FUNCTION fn_get_all_clients(); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_all_clients() TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_all_clients() TO manager;


--
-- Name: FUNCTION fn_get_all_employees(); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_all_employees() TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_all_employees() TO manager;


--
-- Name: FUNCTION fn_get_all_makes(); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_all_makes() TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_all_makes() TO manager;


--
-- Name: FUNCTION fn_get_all_models(); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_all_models() TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_all_models() TO manager;


--
-- Name: FUNCTION fn_get_all_orders(); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_all_orders() TO manager;
GRANT ALL ON FUNCTION public.fn_get_all_orders() TO superadmin;


--
-- Name: FUNCTION fn_get_all_service_categories(); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_all_service_categories() TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_all_service_categories() TO manager;


--
-- Name: FUNCTION fn_get_all_services(); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_all_services() TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_all_services() TO manager;


--
-- Name: FUNCTION fn_get_car_by_id(p_carid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_car_by_id(p_carid integer) TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_car_by_id(p_carid integer) TO manager;


--
-- Name: FUNCTION fn_get_client_by_id(p_clientid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_client_by_id(p_clientid integer) TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_client_by_id(p_clientid integer) TO manager;


--
-- Name: FUNCTION fn_get_department_by_id(p_department_id integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_department_by_id(p_department_id integer) TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_department_by_id(p_department_id integer) TO manager;


--
-- Name: FUNCTION fn_get_employee_by_id(p_employeeid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_employee_by_id(p_employeeid integer) TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_employee_by_id(p_employeeid integer) TO manager;


--
-- Name: FUNCTION fn_get_make_by_id(p_makeid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_make_by_id(p_makeid integer) TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_make_by_id(p_makeid integer) TO manager;


--
-- Name: FUNCTION fn_get_model_by_id(p_modelid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_model_by_id(p_modelid integer) TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_model_by_id(p_modelid integer) TO manager;


--
-- Name: FUNCTION fn_get_order_by_id(p_orderid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_order_by_id(p_orderid integer) TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_order_by_id(p_orderid integer) TO manager;
GRANT ALL ON FUNCTION public.fn_get_order_by_id(p_orderid integer) TO senior_mechanic;


--
-- Name: FUNCTION fn_get_order_by_id_view(p_orderid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_order_by_id_view(p_orderid integer) TO superadmin;


--
-- Name: FUNCTION fn_get_order_for_edit(p_orderid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_order_for_edit(p_orderid integer) TO superadmin;


--
-- Name: FUNCTION fn_get_orderservice_by_id(p_orderserviceid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_orderservice_by_id(p_orderserviceid integer) TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_orderservice_by_id(p_orderserviceid integer) TO manager;


--
-- Name: FUNCTION fn_get_service_by_id(p_serviceid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_service_by_id(p_serviceid integer) TO manager;
GRANT ALL ON FUNCTION public.fn_get_service_by_id(p_serviceid integer) TO superadmin;


--
-- Name: FUNCTION fn_get_servicecategory_by_id(p_categoryid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_get_servicecategory_by_id(p_categoryid integer) TO superadmin;
GRANT ALL ON FUNCTION public.fn_get_servicecategory_by_id(p_categoryid integer) TO manager;


--
-- Name: FUNCTION fn_insert_employee_role(p_employee_id integer, p_role_id integer, p_assigned_by integer, p_is_active boolean); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_insert_employee_role(p_employee_id integer, p_role_id integer, p_assigned_by integer, p_is_active boolean) TO security_officer;
GRANT ALL ON FUNCTION public.fn_insert_employee_role(p_employee_id integer, p_role_id integer, p_assigned_by integer, p_is_active boolean) TO superadmin;


--
-- Name: FUNCTION fn_insert_employeeaccess(p_employeeid integer, p_systemlogin character varying, p_issuedate date, p_isactive boolean, p_passwordcompliant boolean, p_forcepasswordchange boolean); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_insert_employeeaccess(p_employeeid integer, p_systemlogin character varying, p_issuedate date, p_isactive boolean, p_passwordcompliant boolean, p_forcepasswordchange boolean) TO security_officer;
GRANT ALL ON FUNCTION public.fn_insert_employeeaccess(p_employeeid integer, p_systemlogin character varying, p_issuedate date, p_isactive boolean, p_passwordcompliant boolean, p_forcepasswordchange boolean) TO superadmin;


--
-- Name: FUNCTION fn_insert_permission(p_permission_name character varying, p_description text, p_object_type character varying, p_object_name character varying, p_action character varying); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_insert_permission(p_permission_name character varying, p_description text, p_object_type character varying, p_object_name character varying, p_action character varying) TO superadmin;


--
-- Name: FUNCTION fn_update_car(p_carid integer, p_clientid integer, p_modelid integer, p_year integer, p_vin character varying, p_license character varying, p_color character varying); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_update_car(p_carid integer, p_clientid integer, p_modelid integer, p_year integer, p_vin character varying, p_license character varying, p_color character varying) TO manager;
GRANT ALL ON FUNCTION public.fn_update_car(p_carid integer, p_clientid integer, p_modelid integer, p_year integer, p_vin character varying, p_license character varying, p_color character varying) TO superadmin;


--
-- Name: FUNCTION fn_update_client(p_clientid integer, p_fullname text, p_phone text, p_email text, p_address text, p_registration_date date); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_update_client(p_clientid integer, p_fullname text, p_phone text, p_email text, p_address text, p_registration_date date) TO superadmin;


--
-- Name: FUNCTION fn_update_employee(p_employee_id integer, p_fullname character varying, p_position character varying, p_phone character varying, p_email character varying, p_department_id integer, p_hiredate date, p_salary numeric); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_update_employee(p_employee_id integer, p_fullname character varying, p_position character varying, p_phone character varying, p_email character varying, p_department_id integer, p_hiredate date, p_salary numeric) TO manager;
GRANT ALL ON FUNCTION public.fn_update_employee(p_employee_id integer, p_fullname character varying, p_position character varying, p_phone character varying, p_email character varying, p_department_id integer, p_hiredate date, p_salary numeric) TO superadmin;


--
-- Name: FUNCTION fn_update_employee_role(p_employee_role_id integer, p_employee_id integer, p_role_id integer, p_is_active boolean); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_update_employee_role(p_employee_role_id integer, p_employee_id integer, p_role_id integer, p_is_active boolean) TO superadmin;


--
-- Name: FUNCTION fn_update_employeeaccess(p_accessid integer, p_employeeid integer, p_systemlogin character varying, p_isactive boolean, p_passwordcompliant boolean, p_forcepasswordchange boolean); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_update_employeeaccess(p_accessid integer, p_employeeid integer, p_systemlogin character varying, p_isactive boolean, p_passwordcompliant boolean, p_forcepasswordchange boolean) TO security_officer;
GRANT ALL ON FUNCTION public.fn_update_employeeaccess(p_accessid integer, p_employeeid integer, p_systemlogin character varying, p_isactive boolean, p_passwordcompliant boolean, p_forcepasswordchange boolean) TO superadmin;


--
-- Name: FUNCTION fn_update_make(p_id integer, p_name character varying); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_update_make(p_id integer, p_name character varying) TO manager;
GRANT ALL ON FUNCTION public.fn_update_make(p_id integer, p_name character varying) TO superadmin;


--
-- Name: FUNCTION fn_update_model(p_modelid integer, p_makeid integer, p_modelname character varying); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_update_model(p_modelid integer, p_makeid integer, p_modelname character varying) TO manager;
GRANT ALL ON FUNCTION public.fn_update_model(p_modelid integer, p_makeid integer, p_modelname character varying) TO superadmin;


--
-- Name: FUNCTION fn_update_order(p_orderid integer, p_carid integer, p_employeeid integer, p_orderdate date, p_status character varying, p_totalamount numeric); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_update_order(p_orderid integer, p_carid integer, p_employeeid integer, p_orderdate date, p_status character varying, p_totalamount numeric) TO manager;
GRANT ALL ON FUNCTION public.fn_update_order(p_orderid integer, p_carid integer, p_employeeid integer, p_orderdate date, p_status character varying, p_totalamount numeric) TO superadmin;


--
-- Name: FUNCTION fn_update_order_status(p_orderid integer, p_status character varying); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_update_order_status(p_orderid integer, p_status character varying) TO senior_mechanic;
GRANT ALL ON FUNCTION public.fn_update_order_status(p_orderid integer, p_status character varying) TO superadmin;


--
-- Name: FUNCTION fn_update_order_total(); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_update_order_total() TO superadmin;


--
-- Name: FUNCTION fn_update_permission(p_permission_id integer, p_permission_name character varying, p_description text, p_object_type character varying, p_object_name character varying, p_action character varying); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_update_permission(p_permission_id integer, p_permission_name character varying, p_description text, p_object_type character varying, p_object_name character varying, p_action character varying) TO superadmin;


--
-- Name: FUNCTION fn_update_service(p_serviceid integer, p_servicename character varying, p_description text, p_price numeric, p_durationminutes integer, p_categoryid integer); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_update_service(p_serviceid integer, p_servicename character varying, p_description text, p_price numeric, p_durationminutes integer, p_categoryid integer) TO manager;
GRANT ALL ON FUNCTION public.fn_update_service(p_serviceid integer, p_servicename character varying, p_description text, p_price numeric, p_durationminutes integer, p_categoryid integer) TO superadmin;


--
-- Name: FUNCTION fn_update_service_category(p_id integer, p_name character varying, p_description text); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.fn_update_service_category(p_id integer, p_name character varying, p_description text) TO manager;
GRANT ALL ON FUNCTION public.fn_update_service_category(p_id integer, p_name character varying, p_description text) TO superadmin;


--
-- Name: FUNCTION is_weak_password(p_password text); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.is_weak_password(p_password text) TO security_officer;
GRANT ALL ON FUNCTION public.is_weak_password(p_password text) TO superadmin;


--
-- Name: FUNCTION sync_pg_user(); Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON FUNCTION public.sync_pg_user() TO superadmin;


--
-- Name: TABLE audit_log; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.audit_log TO superadmin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.audit_log TO security_officer;
GRANT INSERT,DELETE,UPDATE ON TABLE public.audit_log TO senior_mechanic;
GRANT INSERT,DELETE,UPDATE ON TABLE public.audit_log TO junior_employee;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.audit_log TO manager;


--
-- Name: SEQUENCE audit_log_audit_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.audit_log_audit_id_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.audit_log_audit_id_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.audit_log_audit_id_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.audit_log_audit_id_seq TO manager;


--
-- Name: TABLE cars; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.cars TO superadmin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.cars TO manager;


--
-- Name: SEQUENCE cars_carid_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.cars_carid_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.cars_carid_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.cars_carid_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.cars_carid_seq TO manager;


--
-- Name: TABLE clients; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.clients TO superadmin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.clients TO manager;


--
-- Name: COLUMN clients.clientid; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT(clientid) ON TABLE public.clients TO manager;
GRANT SELECT(clientid) ON TABLE public.clients TO superadmin;


--
-- Name: SEQUENCE clients_clientid_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.clients_clientid_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.clients_clientid_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.clients_clientid_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.clients_clientid_seq TO manager;


--
-- Name: TABLE confidentialdocuments; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.confidentialdocuments TO superadmin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.confidentialdocuments TO security_officer;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.confidentialdocuments TO manager;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.confidentialdocuments TO senior_mechanic;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.confidentialdocuments TO junior_employee;


--
-- Name: SEQUENCE confidentialdocuments_docid_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.confidentialdocuments_docid_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.confidentialdocuments_docid_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.confidentialdocuments_docid_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.confidentialdocuments_docid_seq TO manager;
GRANT SELECT,USAGE ON SEQUENCE public.confidentialdocuments_docid_seq TO junior_employee;


--
-- Name: TABLE departments; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.departments TO superadmin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.departments TO manager;
GRANT SELECT ON TABLE public.departments TO security_officer;
GRANT SELECT ON TABLE public.departments TO senior_mechanic;
GRANT SELECT ON TABLE public.departments TO i_fedorov;


--
-- Name: SEQUENCE departments_department_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.departments_department_id_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.departments_department_id_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.departments_department_id_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.departments_department_id_seq TO manager;


--
-- Name: TABLE employee_roles; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.employee_roles TO superadmin;
GRANT SELECT ON TABLE public.employee_roles TO manager;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.employee_roles TO security_officer;


--
-- Name: SEQUENCE employee_roles_employee_role_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.employee_roles_employee_role_id_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.employee_roles_employee_role_id_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.employee_roles_employee_role_id_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.employee_roles_employee_role_id_seq TO manager;


--
-- Name: TABLE employeeaccess; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.employeeaccess TO superadmin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.employeeaccess TO security_officer;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.employeeaccess TO manager;
GRANT SELECT ON TABLE public.employeeaccess TO senior_mechanic;
GRANT SELECT ON TABLE public.employeeaccess TO junior_employee;
GRANT SELECT ON TABLE public.employeeaccess TO a_smirnov;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.employeeaccess TO m_danilov;


--
-- Name: SEQUENCE employeeaccess_accessid_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.employeeaccess_accessid_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.employeeaccess_accessid_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.employeeaccess_accessid_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.employeeaccess_accessid_seq TO manager;


--
-- Name: TABLE employees; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.employees TO superadmin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.employees TO manager;
GRANT SELECT ON TABLE public.employees TO security_officer;
GRANT SELECT ON TABLE public.employees TO senior_mechanic;
GRANT SELECT ON TABLE public.employees TO i_fedorov;


--
-- Name: COLUMN employees.employeeid; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT(employeeid) ON TABLE public.employees TO manager;


--
-- Name: SEQUENCE employees_employeeid_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.employees_employeeid_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.employees_employeeid_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.employees_employeeid_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.employees_employeeid_seq TO manager;


--
-- Name: TABLE encrypted_data_access_log; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.encrypted_data_access_log TO superadmin;
GRANT SELECT ON TABLE public.encrypted_data_access_log TO manager;
GRANT SELECT ON TABLE public.encrypted_data_access_log TO security_officer;


--
-- Name: SEQUENCE encrypted_data_access_log_access_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.encrypted_data_access_log_access_id_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.encrypted_data_access_log_access_id_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.encrypted_data_access_log_access_id_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.encrypted_data_access_log_access_id_seq TO manager;


--
-- Name: TABLE encryption_keys; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.encryption_keys TO security_officer;
GRANT SELECT,INSERT,UPDATE ON TABLE public.encryption_keys TO superadmin;


--
-- Name: SEQUENCE encryption_keys_key_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT USAGE ON SEQUENCE public.encryption_keys_key_id_seq TO security_officer;
GRANT USAGE ON SEQUENCE public.encryption_keys_key_id_seq TO superadmin;


--
-- Name: TABLE makes; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.makes TO superadmin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.makes TO manager;


--
-- Name: SEQUENCE makes_makeid_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.makes_makeid_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.makes_makeid_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.makes_makeid_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.makes_makeid_seq TO manager;


--
-- Name: TABLE models; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.models TO superadmin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.models TO manager;


--
-- Name: SEQUENCE models_modelid_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.models_modelid_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.models_modelid_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.models_modelid_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.models_modelid_seq TO manager;


--
-- Name: TABLE orders; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.orders TO superadmin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.orders TO manager;
GRANT SELECT ON TABLE public.orders TO senior_mechanic;


--
-- Name: COLUMN orders.status; Type: ACL; Schema: public; Owner: postgres
--

GRANT UPDATE(status) ON TABLE public.orders TO senior_mechanic;


--
-- Name: SEQUENCE orders_orderid_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.orders_orderid_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.orders_orderid_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.orders_orderid_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.orders_orderid_seq TO manager;


--
-- Name: TABLE orderservices; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.orderservices TO superadmin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.orderservices TO manager;


--
-- Name: SEQUENCE orderservices_orderserviceid_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.orderservices_orderserviceid_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.orderservices_orderserviceid_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.orderservices_orderserviceid_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.orderservices_orderserviceid_seq TO manager;


--
-- Name: TABLE password_history; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.password_history TO superadmin;
GRANT SELECT,INSERT ON TABLE public.password_history TO security_officer;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.password_history TO manager;
GRANT SELECT ON TABLE public.password_history TO senior_mechanic;
GRANT SELECT ON TABLE public.password_history TO i_fedorov;


--
-- Name: SEQUENCE password_history_history_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.password_history_history_id_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.password_history_history_id_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.password_history_history_id_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.password_history_history_id_seq TO manager;


--
-- Name: TABLE permissions; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.permissions TO superadmin;
GRANT SELECT ON TABLE public.permissions TO manager;
GRANT SELECT ON TABLE public.permissions TO security_officer;


--
-- Name: SEQUENCE permissions_permission_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.permissions_permission_id_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.permissions_permission_id_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.permissions_permission_id_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.permissions_permission_id_seq TO manager;


--
-- Name: TABLE role_permissions; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.role_permissions TO superadmin;
GRANT SELECT ON TABLE public.role_permissions TO manager;
GRANT SELECT ON TABLE public.role_permissions TO security_officer;


--
-- Name: SEQUENCE role_permissions_role_permission_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.role_permissions_role_permission_id_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.role_permissions_role_permission_id_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.role_permissions_role_permission_id_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.role_permissions_role_permission_id_seq TO manager;


--
-- Name: TABLE roles; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.roles TO superadmin;
GRANT SELECT ON TABLE public.roles TO manager;
GRANT SELECT ON TABLE public.roles TO security_officer;


--
-- Name: SEQUENCE roles_role_id_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.roles_role_id_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.roles_role_id_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.roles_role_id_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.roles_role_id_seq TO manager;


--
-- Name: TABLE servicecategories; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.servicecategories TO superadmin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.servicecategories TO manager;


--
-- Name: SEQUENCE servicecategories_categoryid_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.servicecategories_categoryid_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.servicecategories_categoryid_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.servicecategories_categoryid_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.servicecategories_categoryid_seq TO manager;


--
-- Name: TABLE services; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.services TO superadmin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.services TO manager;


--
-- Name: SEQUENCE services_serviceid_seq; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,USAGE ON SEQUENCE public.services_serviceid_seq TO senior_mechanic;
GRANT ALL ON SEQUENCE public.services_serviceid_seq TO superadmin;
GRANT SELECT,USAGE ON SEQUENCE public.services_serviceid_seq TO security_officer;
GRANT SELECT,USAGE ON SEQUENCE public.services_serviceid_seq TO manager;


--
-- Name: TABLE v_cars; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_cars TO senior_mechanic;
GRANT SELECT ON TABLE public.v_cars TO junior_employee;
GRANT ALL ON TABLE public.v_cars TO superadmin;
GRANT SELECT ON TABLE public.v_cars TO manager;


--
-- Name: TABLE v_clients; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_clients TO senior_mechanic;
GRANT SELECT ON TABLE public.v_clients TO junior_employee;
GRANT ALL ON TABLE public.v_clients TO superadmin;
GRANT SELECT ON TABLE public.v_clients TO manager;


--
-- Name: TABLE v_confidential_documents; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.v_confidential_documents TO superadmin;
GRANT SELECT ON TABLE public.v_confidential_documents TO manager;
GRANT SELECT ON TABLE public.v_confidential_documents TO security_officer;


--
-- Name: TABLE v_confidential_documents_secure; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_confidential_documents_secure TO manager;
GRANT SELECT ON TABLE public.v_confidential_documents_secure TO senior_mechanic;
GRANT SELECT ON TABLE public.v_confidential_documents_secure TO junior_employee;
GRANT SELECT ON TABLE public.v_confidential_documents_secure TO security_officer;
GRANT SELECT ON TABLE public.v_confidential_documents_secure TO superadmin;


--
-- Name: TABLE v_departments; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.v_departments TO superadmin;
GRANT SELECT ON TABLE public.v_departments TO manager;


--
-- Name: TABLE v_employee_access; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.v_employee_access TO superadmin;
GRANT SELECT ON TABLE public.v_employee_access TO manager;


--
-- Name: TABLE v_employees; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.v_employees TO superadmin;
GRANT SELECT ON TABLE public.v_employees TO manager;
GRANT SELECT ON TABLE public.v_employees TO security_officer;


--
-- Name: TABLE v_hr_employees; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_hr_employees TO manager;
GRANT SELECT ON TABLE public.v_hr_employees TO superadmin;


--
-- Name: TABLE v_makes; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.v_makes TO superadmin;
GRANT SELECT ON TABLE public.v_makes TO manager;


--
-- Name: TABLE v_models; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.v_models TO superadmin;
GRANT SELECT ON TABLE public.v_models TO manager;


--
-- Name: TABLE v_order_services; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_order_services TO senior_mechanic;
GRANT SELECT ON TABLE public.v_order_services TO junior_employee;
GRANT ALL ON TABLE public.v_order_services TO superadmin;
GRANT SELECT ON TABLE public.v_order_services TO manager;


--
-- Name: TABLE v_orders; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_orders TO senior_mechanic;
GRANT SELECT ON TABLE public.v_orders TO junior_employee;
GRANT ALL ON TABLE public.v_orders TO superadmin;
GRANT SELECT ON TABLE public.v_orders TO manager;


--
-- Name: TABLE v_public_employees; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_public_employees TO junior_employee;
GRANT SELECT ON TABLE public.v_public_employees TO senior_mechanic;
GRANT SELECT ON TABLE public.v_public_employees TO superadmin;


--
-- Name: TABLE v_secure_clients; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_secure_clients TO manager;
GRANT SELECT ON TABLE public.v_secure_clients TO security_officer;
GRANT SELECT ON TABLE public.v_secure_clients TO junior_employee;
GRANT SELECT ON TABLE public.v_secure_clients TO senior_mechanic;
GRANT SELECT ON TABLE public.v_secure_clients TO superadmin;


--
-- Name: TABLE v_secure_documents; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_secure_documents TO manager;
GRANT SELECT ON TABLE public.v_secure_documents TO security_officer;
GRANT SELECT ON TABLE public.v_secure_documents TO superadmin;


--
-- Name: TABLE v_security_audit_log; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_security_audit_log TO security_officer;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.v_security_audit_log TO superadmin;


--
-- Name: TABLE v_security_employee_access; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_security_employee_access TO security_officer;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.v_security_employee_access TO superadmin;


--
-- Name: TABLE v_security_employee_roles; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_security_employee_roles TO security_officer;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.v_security_employee_roles TO superadmin;


--
-- Name: TABLE v_security_employees; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_security_employees TO security_officer;
GRANT SELECT ON TABLE public.v_security_employees TO superadmin;


--
-- Name: TABLE v_security_encrypted_access_log; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_security_encrypted_access_log TO security_officer;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.v_security_encrypted_access_log TO superadmin;


--
-- Name: TABLE v_security_password_history; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_security_password_history TO security_officer;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.v_security_password_history TO superadmin;


--
-- Name: TABLE v_security_password_history2; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_security_password_history2 TO security_officer;


--
-- Name: TABLE v_security_permissions; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_security_permissions TO security_officer;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.v_security_permissions TO superadmin;


--
-- Name: TABLE v_security_role_permissions; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_security_role_permissions TO security_officer;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.v_security_role_permissions TO superadmin;


--
-- Name: TABLE v_security_roles; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_security_roles TO security_officer;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.v_security_roles TO superadmin;


--
-- Name: TABLE v_service_categories; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.v_service_categories TO superadmin;
GRANT SELECT ON TABLE public.v_service_categories TO manager;


--
-- Name: TABLE v_services; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.v_services TO senior_mechanic;
GRANT SELECT ON TABLE public.v_services TO junior_employee;
GRANT ALL ON TABLE public.v_services TO superadmin;
GRANT SELECT ON TABLE public.v_services TO manager;


--
-- PostgreSQL database dump complete
--

\unrestrict ihOa6finBbcawjePdSqRCs0UUMb7YGf6kuZbxague3wHguNT29MBKWmfVdjrMaP

