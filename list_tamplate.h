#pragma once


#define CREATE_LIST( type, list, CREATE... )                                  \
void create_##list( type** node ) {                                           \
   *node = KALLOCATE( type, (1));                                             \
   (*node)->next = NULL;                                                      \
   CREATE                                                                     \
}

#define ADD_LIST( type, list, param )                                         \
uint32_t add_##list ( type** head, type* node ) {                             \
   type *tmp = *head, *prev = *head;                                          \
   if( !tmp ) {                                                               \
     *head = node; return 0;                                                  \
   }                                                                          \
   while( tmp ) {                                                             \
      if(tmp->param > node->param) {                                          \
         if( tmp == *head ) {                                                 \
            node->next = *head;                                               \
            *head = node;                                                     \
            return 0;                                                         \
         }                                                                    \
         node->next = prev->next;                                             \
         prev->next = node;                                                   \
         return 0;                                                            \
      }                                                                       \
      else if( tmp->param == node->param ) {                                  \
         return -1;                                                           \
      }                                                                       \
      prev = tmp;                                                             \
      tmp = tmp->next;                                                        \
   }                                                                          \
   prev->next = node;                                                         \
   return 0;                                                                  \
}

#define DESTROY_LIST( type, list, FREE )                                      \
void destroy_list_##list( type* head ) {                                      \
   type* tmp = head;                                                          \
   while(( tmp = head )) {                                                    \
      head = head->next;                                                      \
      FREE                                                                    \
   }                                                                          \
   head = NULL;                                                               \
}                                                                             \

#define DESTROY_RECORD_BY_NODE( type, list, FREE )                            \
uint32_t destroy_##list##_by_node( type* node, type** head ) {                \
   type* tmp;                                                                 \
   if( *head == NULL ) { return -1; }                                         \
   if( *head == node ) {                                                      \
     tmp = (*head)->next;                                                     \
     FREE                                                                     \
     *head = tmp;                                                             \
      return 0;                                                               \
   }                                                                          \
   tmp = *head;                                                               \
   while( tmp->next ) {                                                       \
      if( tmp->next == node )  {                                              \
         tmp->next = node->next;                                              \
         FREE                                                                 \
         return 0;                                                            \
      }                                                                       \
      tmp = tmp->next;                                                        \
   }                                                                          \
   return -1;                                                                 \
}
#define DESTROY_RECORD( type, list, typekey, param, FREE )                    \
uint32_t destroy_##list( typekey key, type** head ) {                         \
   type* tmp, *cur;                                                           \
   if( *head == NULL ) { return -1; }                                         \
   if( (*head)->param == key ) {                                              \
     tmp = (*head)->next; cur = *head;                                        \
     FREE                                                                     \
     *head = tmp;                                                             \
      return 0;                                                               \
   }                                                                          \
   tmp = *head;                                                               \
   while( tmp->next ) {                                                       \
      if( tmp->next->param == key )  {                                        \
         cur = tmp->next; tmp->next = cur->next;                              \
         FREE                                                                 \
         return 0;                                                            \
      }                                                                       \
      tmp = tmp->next;                                                        \
   }                                                                          \
   return -1;                                                                 \
}

#define FIND_LIST( type, list, typekey, FIND )                                \
type* find_##list( type* head, typekey key ) {                                \
   type* tmp = head;                                                          \
   while( tmp ) {                                                             \
      FIND                                                                    \
      tmp = tmp->next;                                                        \
   }                                                                          \
   return NULL;                                                               \
}

#define PRINT_LIST( type, list, name, print_str... )                          \
void print_##list ( type* head  ) {                                           \
   type* tmp = head;                                                          \
   printk( "LIST: " name "\n" );                                              \
   while( tmp ) {                                                             \
      printk( print_str );                                                    \
      tmp = tmp->next;                                                        \
   }                                                                          \
   printk("\n");                                                              \
}  
