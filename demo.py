from __future__ import annotations

import argparse
import asyncio
import hashlib
import tempfile
import time

from overlay.core import NodeRecord
from overlay.network import OverlayNetwork


async def run_demo(nodes: int, base_port: int, verbose: bool = False) -> None:
    with tempfile.TemporaryDirectory(prefix="seti-overlay-demo-") as state_dir:
        network = OverlayNetwork(state_dir, count=nodes, base_port=base_port, bootstrap="star")

        def trace(message: str) -> None:
            if verbose:
                print(f"  [подробно] {message}", flush=True)

        try:
            print(f"Запуск локальной сети из {nodes} узлов (начальная схема — «звезда»), "
                  f"порты {base_port}–{base_port + nodes - 1}...")
            trace("Поднимаю узлы, выполняю bootstrap и первичную сходимость DHT.")
            await network.start()
            trace(f"Сеть готова; сходимость: "
                  f"{'да' if network.summary()['operationally_converged'] else 'нет'}.")

            print("\n[1/5] Взаимная аутентификация узлов по TLS")
            peer = network.node(1)
            trace(f"Узел {peer.identity.node_id[:12]} отправляет PING узлу "
                  f"{network.node(0).identity.node_id[:12]}.")
            response = await peer.rpc(network.contacts[0], "PING", {})
            assert response["node_id"] == network.node(0).identity.node_id
            trace("Удалённый узел ответил, сертификат и NodeID проверены.")
            print(f"ПРОЙДЕНО: узел {peer.identity.node_id[:12]} прошёл аутентификацию "
                  f"узла {response['node_id'][:12]}")

            print("\n[2/5] Поиск узла в DHT")
            lookup_client = network.node(1)
            lookup_target = network.node(nodes - 1).identity.node_id
            trace("Удаляю цель из таблицы инициатора, чтобы поиск выполнялся через DHT.")
            lookup_client._remove_contact(lookup_target)
            trace(f"Запускаю FIND_NODE для цели {lookup_target[:12]}.")
            result = await lookup_client.lookup_node(lookup_target)
            assert any(contact.node_id == lookup_target for contact in result.contacts)
            trace(f"Поиск завершён: итераций {result.iterations}, RPC-запросов {result.rpc_count}.")
            print(f"ПРОЙДЕНО: цель найдена за {result.iterations} итераций; "
                  f"RPC-запросов: {result.rpc_count}, время: {result.duration_ms:.1f} мс")

            print("\n[3/5] Сохранение и получение подписанной записи")
            publisher = network.node(0)
            reader = network.node(nodes - 1)
            key = hashlib.sha256(b"seti-demo-record").hexdigest()
            record = NodeRecord.create(
                publisher.identity,
                (f"{publisher.contact.host}:{publisher.contact.port}",),
                publisher.record_sequence + 1,
                network.config.record_ttl_seconds,
                publisher.box.public_bytes,
            )
            trace("Создаю подписанную NodeRecord и сохраняю её с репликацией в DHT.")
            assert await publisher.put_record(key, record), "Запись не удалось реплицировать"
            trace("Запись сохранена; запрашиваю её с другого узла.")
            retrieved = await reader.get_record(key)
            assert retrieved is not None and retrieved.validate()
            assert retrieved.node_id == publisher.identity.node_id
            trace("Подпись и идентификатор владельца записи проверены.")
            print(f"ПРОЙДЕНО: подпись записи проверена, запись получена; "
                  f"подтверждений реплик: "
                  f"{len(publisher.last_store_diagnostics['acknowledged_replica_ids'])}")

            print("\n[4/5] Туннель с двумя ретрансляторами и зашифрованное сообщение")
            sender = network.node(1)
            receiver = network.node(nodes - 1)
            message = "Демо: защищённое сообщение через оверлейную сеть"
            trace("Строю туннель с двумя ретрансляторами.")
            tunnel = await sender.build_tunnel(receiver.identity.node_id)
            assert len(tunnel["route"]) == network.config.required_relays
            trace(f"Туннель активен; ретрансляторы: "
                  f"{', '.join(peer.node_id[:12] for peer in tunnel['route'])}.")
            trace("Шифрую сообщение для получателя и отправляю по туннелю.")
            delivery = await sender.send_via_tunnel(tunnel, message)
            assert delivery["delivered"]
            assert receiver.received_messages[-1]["text"] == message
            trace("Получатель расшифровал сообщение; закрываю туннель.")
            await sender.close_tunnel(tunnel)
            print(f"ПРОЙДЕНО: сообщение доставлено через ретрансляторы "
                  f"({len(delivery['relay_ids'])}) за {delivery['e2e_ms']:.1f} мс; туннель закрыт")

            print("\n[5/5] Отказ ретранслятора и восстановление доставки")
            failed_tunnel = await sender.build_tunnel(receiver.identity.node_id)
            failed_relay = failed_tunnel["route"][0]
            failed_node = next(node for node in network.nodes if node.identity.node_id == failed_relay.node_id)
            trace(f"Останавливаю ретранслятор {failed_relay.node_id[:12]}.")
            await failed_node.stop()
            try:
                try:
                    trace("Проверяю доставку по исходному маршруту.")
                    await sender.send_via_tunnel(failed_tunnel, "Сообщение по отказавшему маршруту")
                except (OSError, TimeoutError):
                    print("ПРОЙДЕНО: исходный маршрут отказал, как и ожидалось")
                else:
                    raise AssertionError("Сообщение неожиданно прошло через остановленный ретранслятор")

                recovery_started = time.perf_counter()
                trace("Перестраиваю маршрут без отказавшего ретранслятора и повторяю доставку.")
                recovery = await sender.send_with_recovery(
                    receiver.identity.node_id,
                    "Демо: доставка восстановлена после отказа ретранслятора",
                    failed_relay_ids={failed_relay.node_id},
                )
                recovery_ms = (time.perf_counter() - recovery_started) * 1000
                assert recovery["delivered"]
                assert receiver.received_messages[-1]["text"] == (
                    "Демо: доставка восстановлена после отказа ретранслятора"
                )
                trace("Сообщение получено по новому маршруту.")
            finally:
                trace("Запускаю отказавший узел обратно.")
                await failed_node.start()

            await sender.close_tunnel(failed_tunnel)
            recovered_tunnel = sender.tunnels[recovery["tunnel_id"]]
            await sender.close_tunnel(recovered_tunnel)
            print(f"ПРОЙДЕНО: ретранслятор {failed_relay.node_id[:12]} остановлен; "
                  f"маршрут перестроен, сообщение доставлено за {recovery_ms:.1f} мс")
            print("\nВсе 5 сценариев демо успешно пройдены.")
        finally:
            await network.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Запуск пяти демонстрационных сценариев SETI Overlay.")
    parser.add_argument("--nodes", type=int, default=12, choices=range(12, 16),
                        help="число локальных узлов (12–15; по умолчанию: 12)")
    parser.add_argument("--port", type=int, default=23000,
                        help="первый TCP-порт (по умолчанию: 23000)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="показывать подробный ход выполнения сценариев")
    args = parser.parse_args()
    asyncio.run(run_demo(args.nodes, args.port, args.verbose))


if __name__ == "__main__":
    main()
