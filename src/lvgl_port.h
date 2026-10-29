#ifndef LVGL_PORT_H
#define LVGL_PORT_H



#ifdef __cplusplus
extern "C" {
#endif


void lvgl_port_init(void);
void lvgl_port_lock(int timeout_ms);
void lvgl_port_unlock(void);


#ifdef __cplusplus
}
#endif



#endif










