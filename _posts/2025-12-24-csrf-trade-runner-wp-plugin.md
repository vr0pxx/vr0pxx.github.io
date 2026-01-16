---
title: "CVE-2025-67625"
date: 2025-12-24
categories: ['CVE', '2025']
tags: ['CSRF', 'WordPress']
severity: 'Medium'
cve_id: 'CVE-2025-67625'
cvss_score: '4.3'
image: /assets/img/posts/security-research/CVE-2025-67625/CVE-2025-67625.png
---

## Introducción

En este post documento mi primer CVE: **CVE-2025-67625**, una vulnerabilidad de tipo **Cross-Site Request Forgery (CSRF)** identificada en el plugin de WordPress **Trade Runner** (versiones **<= 3.14**).

El problema se origina porque una acción sensible dentro del panel de administración puede ejecutarse mediante una petición **GET** sin ningún tipo de protección anti-CSRF (nonce), lo cual permite que un atacante fuerce a un usuario autenticado (por ejemplo, un administrador) a ejecutar dicha acción simplemente al visitar una página o enlace malicioso.

---

## Resumen del CVE

- **CVE ID:** CVE-2025-67625  
- **Tipo de vulnerabilidad:** Cross-Site Request Forgery (CSRF)  
- **Producto afectado:** Trade Runner (WordPress Plugin)  
- **Versiones vulnerables:** <= 3.14  
- **Severidad:** Medium  
- **CVSS:** 4.3  

---

## Impacto

Este CSRF puede ser explotado para disparar el flujo de conexión del plugin, provocando:

- La ejecución del endpoint/página de administración `traderunner_connect`.
- La eliminación de la API key actual de WooCommerce.
- La generación de una nueva API key automáticamente.
- La ruptura inmediata de la integración entre el sitio y Trade Runner (**Denial of Service**).
- Una redirección automática hacia un dominio externo (`traderunner.omnivore.com.au`), lo que puede confundir al administrador y sacarlo del contexto del panel.

Aunque este tipo de vulnerabilidad requiere interacción del usuario (que el administrador visite una URL o página controlada por el atacante), en la práctica es un escenario realista mediante ingeniería social, enlaces incrustados o contenido malicioso en sitios externos.

---

## Prueba de Concepto (PoC) / Cómo reproducir

1. Instalar y activar los plugins `traderunner` y `woocommerce`.  
   *(WooCommerce es requerido para que la clase `TradeRunnerAdmin` cargue correctamente).*

2. Iniciar sesión como **administrador** y configurar el plugin para que el sitio quede conectado.

3. Crear una página HTML maliciosa con un `<img>` o utilizar un enlace directo apuntando al endpoint vulnerable:

   ```html
   <img src="https://YOUR-SITE.com/wp-admin/admin.php?page=traderunner_connect">
   ```

4. Engañar al administrador autenticado para que visite esta página HTML o abra el enlace.

5. El navegador realizará automáticamente una solicitud GET al endpoint `traderunner_connect`.

6. La función `connect()` se ejecutará, eliminando la API key existente de WooCommerce y generando una nueva.

7. Luego, la función realizará una redirección hacia una URL externa del dominio `traderunner.omnivore.com.au`.

8. Resultado / Impacto:
La conexión del sitio con Trade Runner se rompe de inmediato (Denial of Service), y el administrador es redirigido fuera de su propio sitio/panel de administración, causando confusión.

---

## Detalles técnicos

El plugin registra la página de administración `traderunner_connect` mediante `add_submenu_page()`. Cuando un usuario con permisos adecuados accede a esa página, se ejecuta el método `connect()`.

El problema es que `connect()` ejecuta una acción que cambia el estado del sistema (creación/regeneración de credenciales) a través de una solicitud GET y sin verificar un nonce, lo cual permite ataques CSRF.

Fragmento relevante:

```php
public function initAdminMenu() {
    //...
    add_submenu_page( null, null, null, 'manage_options', self::flavour . '_connect', array($this, 'connect'));
}

public function connect() {
    if (!current_user_can( 'manage_options'))  {
        wp_die(__('You do not have sufficient permissions to access this page.'));
    }

    // VULNERABILITY: This state-changing function is called on a GET request
    // with no nonce check.
    $key_details = $this->create_update_api_key(); 
    
    $url = self::baseUrl . '?' . ...;
    
    // The "logout" symptom is this redirect:
    wp_redirect( $url );
}
```

### ¿Por qué esto es un CSRF?

- Un administrador autenticado en WordPress mantiene cookies de sesión válidas.

- Un atacante puede forzar un request con un simple `<img src=...>` o un link.

- WordPress enviará automáticamente las cookies (sesión activa).

- La acción se ejecuta como si el usuario la hubiese solicitado intencionalmente.

- Debido a la ausencia de `wp_verify_nonce()` / `check_admin_referer()`, no hay protección anti-CSRF efectiva.



En este caso, el cambio de estado ocurre al ejecutar `create_update_api_key()`, que invalida credenciales anteriores y genera nuevas, causando pérdida de conectividad.

---

## Referencias

- [CVE Record](https://www.cve.org/CVERecord?id=CVE-2025-67625)
- [Wordfence](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/traderunner/trade-runner-314-cross-site-request-forgery)


---

# Créditos

Investigación y reporte por César Arias Rodríguez (vr0px)

